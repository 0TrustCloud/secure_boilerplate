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

type ViewDefinition struct {
	Name        string   `yaml:"name"`
	Path        string   `yaml:"path"`
	Template    string   `yaml:"template"`
	Policy      string   `yaml:"policy"` // "public" or "secure"
	DataSources []string `yaml:"data_sources"`
}

type RBACConfig struct {
	Roles []struct {
		Name        string   `yaml:"name"`
		Permissions []string `yaml:"permissions"`
	} `yaml:"roles"`
}

type ABACConfig struct {
	Policies []struct {
		Subject  string `yaml:"subject"`
		Action   string `yaml:"action"`
		Resource string `yaml:"resource"`
		Effect   string `yaml:"effect"`
	} `yaml:"policies"`
}

type MasterConfig struct {
	Server struct {
		ServiceName string `yaml:"service_name"`
		Host        string `yaml:"host"`
		Domain      string `yaml:"domain"`
	} `yaml:"server"`
	Files struct {
		RbacPath  string `yaml:"rbac_path"`
		AbacPath  string `yaml:"abac_path"`
		ViewsPath string `yaml:"views_path"`
	} `yaml:"files"`
	Views []ViewDefinition                `yaml:"views"`
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
	ServiceKeys  *service_keys.ServiceKeyManager
}

type RouteModule struct {
	Server *Server
	Views  []ViewDefinition
}

type PlatformControl struct {
	Router *secure_network.Router
}

func (pc *PlatformControl) Shutdown(ctx context.Context) error {
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

	var cfg MasterConfig
	cfgData, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Boilerplate Critical: Missing configuration footprint: %v", err)
	}
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("Boilerplate Critical: Malformed configuration parameters: %v", err)
	}

	if cfg.Files.ViewsPath != "" && len(cfg.Views) == 0 {
		if vData, err := os.ReadFile(cfg.Files.ViewsPath); err == nil {
			var secondaryViews struct {
				Views []ViewDefinition `yaml:"views"`
			}
			if yaml.Unmarshal(vData, &secondaryViews) == nil {
				cfg.Views = secondaryViews.Views
			}
		}
	}

	concreteProvider := provider.(*webauthnext.Provider)
	db := ui.DB 

	jwtSigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed generating cryptographic signing key: %v", err)
	}

	store := ultimate_db.NewBTreeKVStore(db)
	lockManager := ultimate_db.New2PLLockManager()

	serviceName := cfg.Server.ServiceName
	if serviceName == "" {
		serviceName = "iam_edge_node"
	}

	sdfEngine, err := secure_data_format.New(store, lockManager, serviceName, jwtSigningKey)
	if err != nil {
		log.Fatalf("Failed to initialize SDF engine context: %v", err)
	}

	// 1. Properly initialize the SessionManager using the container signing primitives
	sessionManager := secure_policy.NewSessionManager(sdfEngine, &jwtSigningKey.PublicKey)

	// 2. Invoke the native constructor to cleanly hydrate the WebAuthn Provider state
	realProvider, err := webauthnext.New(ui, sessionManager, sdfEngine, serviceName, cfg.Server.Host, cfg.Server.Domain)
	if err != nil {
		log.Fatalf("Failed to execute native provider constructor: %v", err)
	}
	// Hydrate the shell pointer passed from the application block
	*concreteProvider = *realProvider

	sysLogger, err := logger.NewLogDispatcher(serviceName, 1000, sdfEngine)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	skm := service_keys.NewServiceKeyManager(sdfEngine, concreteProvider, sysLogger)
	pe := secure_policy.NewPolicyEngine(sdfEngine)

	if cfg.Files.RbacPath != "" {
		if rbacData, err := os.ReadFile(cfg.Files.RbacPath); err == nil {
			var rbacCfg RBACConfig
			if yaml.Unmarshal(rbacData, &rbacCfg) == nil {
				for _, role := range rbacCfg.Roles {
					for _, perm := range role.Permissions {
						_ = pe.GrantPermission([]byte(role.Name), perm)
					}
				}
				log.Printf("[Container Bootstrap] Loaded structural RBAC controls from %s", cfg.Files.RbacPath)
			}
		}
	}

	if cfg.Files.AbacPath != "" {
		if abacData, err := os.ReadFile(cfg.Files.AbacPath); err == nil {
			var abacCfg ABACConfig
			if yaml.Unmarshal(abacData, &abacCfg) == nil {
				for _, policy := range abacCfg.Policies {
					_ = pe.AddPolicy([]byte(policy.Subject), policy.Action, policy.Resource, policy.Effect, nil)
				}
				log.Printf("[Container Bootstrap] Loaded conditional ABAC controls from %s", cfg.Files.AbacPath)
			}
		}
	}

	// 3. Pass the guaranteed, concrete sessionManager instance directly into the router
	r, err := secure_network.NewRouter(
		sdfEngine,
		ui,
		"session_id",
		pe,
		sessionManager, 
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

	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)

	meshNode, err := secure_network.NewMeshNode(sdfEngine, gatewayPubKey, sysLogger)
	if err != nil {
		log.Fatalf("Failed creating mesh node: %v", err)
	}

	searchEngine, err := orchid_sync.NewEngine(db, meshNode, sysLogger)
	if err != nil {
		log.Fatalf("Failed to initialize OrchidSync: %v", err)
	}

	admin := identity_provider.NewAdminController(db, pe, bus, sysLogger, sdfEngine)
	audit := identity_provider.NewAuditController(searchEngine, ui, sdfEngine)
	sysLogger.RegisterExporter(audit)

	scim := identity_provider.NewSCIMDaemon(db, bus, sysLogger, sdfEngine)
	go scim.Start()

	for _, app := range cfg.Apps {
		_ = admin.RegisterApp(app, "system_bootstrap")
	}

	for _, user := range cfg.Users {
		_ = admin.AssignUserToApp(user, user.SessionID, "system_bootstrap")
	}

	hostAddr := cfg.Server.Host + ":443"
	if cfg.Server.Host == "" {
		hostAddr = "localhost:443"
	}
	secure_bootstrap.BootstrapAuth(r, db, concreteProvider, meshNode, hostAddr, sysLogger)

	identity_provider.RegisterRoutes(r, admin, audit, pe, sessionManager, sysLogger, configPath)

	s := &Server{
		UI:           ui,
		AuthProvider: concreteProvider,
		SearchEngine: searchEngine,
		DB:           db,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
		Logger:       sysLogger,
		MeshNode:     meshNode,
		ServiceKeys:  skm,
	}

	if ui != nil {
		r.Mux.HandleFunc("GET /logout", func(w http.ResponseWriter, req *http.Request) {
			secure_bootstrap.HandleLogout(w, req)
		})

		r.Mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, req *http.Request) {
			c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
			secure_bootstrap.RequireAuth(r, func(ctx *guikit.Context) {
				ctx.Data["Title"] = "Identity Dashboard"
				ui.Render(ctx, "views/portal")
			})(c)
		})
	}

	routeRegister(&RouteModule{Server: s, Views: cfg.Views})

	log.Printf("Booting Zero-Trust Identity Hub on %s", hostAddr)
	r.Port = "443"
	go r.Boot() 

	return &PlatformControl{Router: r}
}
