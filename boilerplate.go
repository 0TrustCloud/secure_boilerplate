package secure_boilerplate

import (
	"log"
	"net/http"
	"os"

	"github.com/gddisney/guikit"
	"github.com/gddisney/identity_provider"
	"github.com/gddisney/orchid_sync"
	"github.com/gddisney/secure_bootstrap"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
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
}

type RouteModule struct {
	Server *Server
}

// Public registers endpoints that explicitly bypass Zero-Trust authentication
func (rm *RouteModule) Public(pattern string, handler http.HandlerFunc) {
	rm.Server.Router.Mux.HandleFunc(pattern, handler)
}

// Secure registers an endpoint that enforces Zero-Trust authentication
func (rm *RouteModule) Secure(pattern string, handler http.HandlerFunc) {
	// Adapter: Wrap standard handler into guikit-compatible func
	protected := func(c *guikit.Context) {
		handler(c.W, c.R)
	}

	rm.Server.Router.Mux.HandleFunc(pattern, rm.Server.UI.SecureHeaders(func(w http.ResponseWriter, r *http.Request) {
		c := &guikit.Context{W: w, R: r, Data: make(map[string]interface{})}
		// Correct signature: Pass router then the handler function, then execute with context
		secure_bootstrap.RequireAuth(rm.Server.Router, protected)(c)
	}))
}

func Start(ui *guikit.GUIKit, configPath string, provider IdentityProvider, routeRegister func(routes *RouteModule)) {
	var cfg Config
	if cfgData, err := os.ReadFile(configPath); err == nil {
		_ = yaml.Unmarshal(cfgData, &cfg)
	}

	concreteProvider := provider.(*webauthnext.Provider)
	searchEngine, _ := orchid_sync.NewEngine("iam_data.db", 443, concreteProvider)

	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	bus := make(chan secure_network.SystemEvent, 10)
	r.LocalBus = bus

	pe := secure_policy.NewPolicyEngine(db)
	admin := &identity_provider.AdminController{DB: db, PolicyEngine: pe, LocalBus: bus}
	audit := identity_provider.NewAuditController(db, searchEngine, ui)
	scim := identity_provider.NewSCIMDaemon(db, bus)

	go scim.Start()

	for _, app := range cfg.Apps { _ = admin.RegisterApp(app) }
	for _, user := range cfg.Users { _ = admin.AssignUserToApp(user, user.SessionID) }

	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)

	meshNode, _ := secure_network.NewMeshNode(db, gatewayPubKey)

	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, "localhost:443")
	identity_provider.RegisterRoutes(r, admin, audit, pe, concreteProvider.SessionManager)

	s := &Server{UI: ui, AuthProvider: provider, SearchEngine: searchEngine, DB: db, Router: r, Admin: admin, Audit: audit}

	// Register UI routes with proper context adapters
	if r.GUIKit != nil {
		r.GUIKit.Mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
			secure_bootstrap.HandleLogout(w, r)
		})
		
		// Use RequireAuth directly in a way that respects the context
		r.GUIKit.Mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			c := &guikit.Context{W: w, R: r, Data: make(map[string]interface{})}
			secure_bootstrap.RequireAuth(r.Router, func(c *guikit.Context) {
				c.Data["Title"] = "Identity Dashboard"
				r.GUIKit.Render(c, "views/portal")
			})(c)
		})
	}

	routeRegister(&RouteModule{Server: s})

	log.Println("Booting Zero-Trust Identity Hub on :443")
	_ = edgeNode.Start("443", r.TLSConfig)
}
