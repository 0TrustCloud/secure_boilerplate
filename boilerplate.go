package secure_boilerplate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"os"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/identity_provider"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/orchid_sync"
	"github.com/0TrustCloud/secure_bootstrap"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/service_keys"
	"github.com/0TrustCloud/ultimate_db"
	webauthnext "github.com/0TrustCloud/auth_provider"
	"gopkg.in/yaml.v3"
)

type IdentityProvider interface{}

type Config struct {
	Apps  []identity_provider.Application `yaml:"apps"`
	Users []identity_provider.Identity    `yaml:"users"`
}

type Server struct {
	UI           *guikit.GUIKit
	AuthProvider IdentityProvider
	SearchEngine *orchid_sync.Engine
	DB           *ultimate_db.DB
	Router       *secure_network.Router
	Admin        *identity_provider.AdminController
	Audit        *identity_provider.AuditController
	Logger       *logger.LogDispatcher
	MeshNode     *secure_network.MeshNode
}

type RouteModule struct {
	Server *Server
}

type PlatformControl struct {
	Router *secure_network.Router
}

func (pc *PlatformControl) Shutdown(ctx context.Context) error {
	// Satisfies the graceful control plane shutdown lifecycle hooks
	return nil
}

func (rm *RouteModule) Public(pattern string, handler http.HandlerFunc) {
	rm.Server.Router.Mux.HandleFunc(pattern, handler)
}

func (rm *RouteModule) Secure(pattern string, handler http.HandlerFunc) {
	protected := func(c *guikit.Context) {
		handler(c.W, c.R)
	}

	rm.Server.Router.Mux.HandleFunc(
		pattern,
		rm.Server.UI.SecureHeaders(
			func(w http.ResponseWriter, req *http.Request) {
				c := &guikit.Context{
					W:    w,
					R:    req,
					Data: make(map[string]interface{}),
				}
				secure_bootstrap.RequireAuth(rm.Server.Router, protected)(c)
			},
		),
	)
}

func Start(
	ui *guikit.GUIKit,
	configPath string,
	provider IdentityProvider,
	routeRegister func(routes *RouteModule),
) *PlatformControl {

	// --------------------------------------------------
	// CONFIG
	// --------------------------------------------------
	var cfg Config
	if cfgData, err := os.ReadFile(configPath); err == nil {
		_ = yaml.Unmarshal(cfgData, &cfg)
	}

	// --------------------------------------------------
	// PROVIDER & DB
	// --------------------------------------------------
	concreteProvider := provider.(*webauthnext.Provider)
	db := ui.DB 

	// --------------------------------------------------
	// SECURE DATA FORMAT (SDF) CORE ENGINE
	// --------------------------------------------------
	jwtSigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed generating cryptographic signing key: %v", err)
	}

	var store ultimate_db.KVStore
	var lockManager ultimate_db.LockManager

	sdfEngine, err := secure_data_format.New(store, lockManager, "iam_edge_node", jwtSigningKey)
	if err != nil {
		log.Fatalf("Failed to initialize SDF engine context: %v", err)
	}

	// --------------------------------------------------
	// LOGGER
	// --------------------------------------------------
	sysLogger, err := logger.NewLogDispatcher("iam_edge_node", 1000, sdfEngine)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// --------------------------------------------------
	// POLICY ENGINE
	// --------------------------------------------------
	pe := secure_policy.NewPolicyEngine(sdfEngine)

	// --------------------------------------------------
	// ROUTER (Explicit Wire-up)
	// --------------------------------------------------
	r, err := secure_network.NewRouter(
		db,
		ui,
		"session_id", // Target Cookie
		pe,
		concreteProvider.SessionManager,
		sysLogger,
	)
	if err != nil {
		log.Fatalf("Failed to initialize Router: %v", err)
	}

	if ui != nil {
		r.Mux.Handle("/index", ui.Mux)
	}

	bus := make(chan secure_network.SystemEvent, 128)
	r.LocalBus = bus

	// --------------------------------------------------
	// MESH NODE (Explicit Wire-up)
	// --------------------------------------------------
	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)

	meshNode, err := secure_network.NewMeshNode(
		sdfEngine,
		gatewayPubKey,
		sysLogger,
	)
	if err != nil {
		log.Fatalf("Failed creating mesh node: %v", err)
	}

	// --------------------------------------------------
	// SEARCH ENGINE
	// --------------------------------------------------
	searchEngine, err := orchid_sync.NewEngine(
		db,
		meshNode,
		sysLogger,
	)
	if err != nil {
		log.Fatalf("Failed to initialize OrchidSync: %v", err)
	}

	// --------------------------------------------------
	// CONTROLLERS
	// --------------------------------------------------
	admin := identity_provider.NewAdminController(db, pe, bus, sysLogger, sdfEngine)
	audit := identity_provider.NewAuditController(searchEngine, ui, sdfEngine)
	sysLogger.RegisterExporter(audit)

	scim := identity_provider.NewSCIMDaemon(db, bus, sysLogger, sdfEngine)
	go scim.Start()

	// --------------------------------------------------
	// BOOTSTRAP APPS & USERS
	// --------------------------------------------------
	for _, app := range cfg.Apps {
		if err := admin.RegisterApp(app, "system_bootstrap"); err != nil {
			sysLogger.Error("Failed registering app: " + err.Error())
		}
	}

	for _, user := range cfg.Users {
		if err := admin.AssignUserToApp(user, user.SessionID, "system_bootstrap"); err != nil {
			sysLogger.Error("Failed assigning user: " + err.Error())
		}
	}

	// --------------------------------------------------
	// ROUTE REGISTRATION
	// --------------------------------------------------
	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, "localhost:443", sysLogger)

	identity_provider.RegisterRoutes(
		r,
		admin,
		audit,
		pe,
		concreteProvider.SessionManager,
		sysLogger,
		configPath,
	)

	// --------------------------------------------------
	// SERVER OBJECT
	// --------------------------------------------------
	s := &Server{
		UI:           ui,
		AuthProvider: provider,
		SearchEngine: searchEngine,
		DB:           db,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
		Logger:       sysLogger,
		MeshNode:     meshNode,
	}

	// --------------------------------------------------
	// DEFAULT ROUTES
	// --------------------------------------------------
	if ui != nil {
		ui.Mux.HandleFunc("GET /logout", func(w http.ResponseWriter, req *http.Request) {
			secure_bootstrap.HandleLogout(w, req)
		})

		ui.Mux.HandleFunc("GET /", func(w http.ResponseWriter, req *http.Request) {
			c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
			secure_bootstrap.RequireAuth(r, func(ctx *guikit.Context) {
				ctx.Data["Title"] = "Identity Dashboard"
				ui.Render(ctx, "views/portal")
			})(c)
		})
	}

	// --------------------------------------------------
	// CUSTOM ROUTES
	// --------------------------------------------------
	routeRegister(&RouteModule{Server: s})

	// --------------------------------------------------
	// START SERVER
	// --------------------------------------------------
	log.Println("Booting Zero-Trust Identity Hub on :443")
	
	r.Port = "443"
	go r.Boot() 

	return &PlatformControl{Router: r}
}
