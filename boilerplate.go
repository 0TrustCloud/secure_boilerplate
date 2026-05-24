package boilerplate

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

// IdentityProvider is an empty interface. This allows us to inject dynamic providers 
// (like webauthnext) without triggering Go's strict cross-module interface compiler checks.
type IdentityProvider interface{}

// Config defines the structure for YAML bootstrap data
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

// Start enforces the boot sequence, loading config and initializing the identity stack
func Start(configPath string, provider IdentityProvider, routeRegister func(s *Server)) {
	// 1. Load YAML Configuration
	cfgData, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config file at %s: %v", configPath, err)
	}
	
	var cfg Config
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("Failed to parse YAML config: %v", err)
	}

	// 2. Boot GUI Engine (Mirrors secure_logger.go)
	ui, err := guikit.New("ui.db", "ui.wal")
	if err != nil {
		log.Fatalf("Failed to boot guikit: %v", err)
	}

	// 3. Safe Type Assertion for Search Engine
	// orchid_sync explicitly requires *webauthnext.Provider. We safely assert it here.
	concreteProvider, ok := provider.(*webauthnext.Provider)
	if !ok {
		log.Fatalf("FATAL: Provided IdentityProvider is not a *webauthnext.Provider")
	}

	searchEngine, err := orchid_sync.NewEngine("data.db", 443, concreteProvider)
	if err != nil {
		log.Fatalf("Failed to boot search engine: %v", err)
	}

	// 4. Network and Router Initialization
	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	// 5. Initialize Identity & Security Stack
	bus := make(chan secure_network.SystemEvent, 10)
	pe := secure_policy.NewPolicyEngine(db)

	admin := &identity_provider.AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
	}

	audit := identity_provider.NewAuditController(db, searchEngine, ui)
	scim := identity_provider.NewSCIMDaemon(db, bus)

	go scim.Start()

	// 6. Execute YAML Bootstrap Flow
	for _, app := range cfg.Apps {
		if err := admin.RegisterApp(app); err != nil {
			log.Printf("Bootstrap error: failed to register app %s: %v", app.ID, err)
		}
	}
	for _, user := range cfg.Users {
		if err := admin.AssignUserToApp(user, user.SessionID); err != nil {
			log.Printf("Bootstrap error: failed to assign user %s: %v", user.Subject, err)
		}
	}

	// 7. Identity & Hardware Handshake (Mirrors secure_logger.go exactly)
	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)
	gatewayAddress := "localhost:443"

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil {
		log.Fatalf("Mesh Node instantiation failed: %v", err)
	}

	// 8. Strict Auth Flow Bootstrap
	secure_bootstrap.BootstrapAuth(r, provider, meshNode, gatewayAddress)

	// 9. Register pure identity routes
	identity_provider.RegisterRoutes(r, admin, audit, pe)

	// 10. Server Definition & Protected UI Routes
	s := &Server{
		UI:           ui,
		AuthProvider: provider,
		SearchEngine: searchEngine,
		DB:           db,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
	}

	// Wire the main portal directly in the boilerplate
	if r.GUIKit != nil {
		r.GUIKit.Get("/", secure_bootstrap.RequireAuth(r, func(c *guikit.Context) {
			c.Data["Title"] = "Identity Portal"
			r.GUIKit.Render(c, "views/portal")
		}))
	}

	// 11. Execute Application-Specific Logic
	routeRegister(s)

	// 12. Final Execution
	log.Println("Booting Zero-Trust Edge Node on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
