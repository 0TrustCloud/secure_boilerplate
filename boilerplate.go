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

func (rm *RouteModule) Public(pattern string, handler http.HandlerFunc) {
	rm.Server.Router.Mux.HandleFunc(pattern, handler)
}

func (rm *RouteModule) Secure(pattern string, handler http.HandlerFunc) {
	protected := func(c *guikit.Context) {
		handler(c.W, c.R)
	}
	rm.Server.Router.Mux.HandleFunc(pattern, rm.Server.UI.SecureHeaders(func(w http.ResponseWriter, req *http.Request) {
		c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
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
	r := edgeNode.Router
	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	bus := make(chan secure_network.SystemEvent, 10)
	r.LocalBus = bus
	pe := secure_policy.NewPolicyEngine(edgeNode.DB)
	admin := &identity_provider.AdminController{DB: edgeNode.DB, PolicyEngine: pe, LocalBus: bus}
	audit := identity_provider.NewAuditController(edgeNode.DB, searchEngine, ui)
	scim := identity_provider.NewSCIMDaemon(edgeNode.DB, bus)
	go scim.Start()

	for _, app := range cfg.Apps { _ = admin.RegisterApp(app) }
	for _, user := range cfg.Users { _ = admin.AssignUserToApp(user, user.SessionID) }

	keyTxn := edgeNode.DB.BeginTxn()
	gatewayPubKey, _ := edgeNode.DB.Read(99, keyTxn, []byte("mesh_noise_pub"))
	edgeNode.DB.CommitTxn(keyTxn)

	meshNode, _ := secure_network.NewMeshNode(edgeNode.DB, gatewayPubKey)
	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, "localhost:443")
	identity_provider.RegisterRoutes(r, admin, audit, pe, concreteProvider.SessionManager)

	s := &Server{UI: ui, AuthProvider: provider, SearchEngine: searchEngine, DB: edgeNode.DB, Router: r, Admin: admin, Audit: audit}

	// Register UI routes correctly using scope-captured 'r' (router) and 'ui'
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

	routeRegister(&RouteModule{Server: s})

	log.Println("Booting Zero-Trust Identity Hub on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
