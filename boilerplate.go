package secure_boilerplate

import (
	"log"
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

func Start(configPath string, provider IdentityProvider, routeRegister func(s *Server)) {
	// 1. Load Configuration
	cfgData, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// 2. Type Assert the Provider immediately
	concreteProvider, ok := provider.(*webauthnext.Provider)
	if !ok {
		log.Fatalf("FATAL: Provided IdentityProvider is not a *webauthnext.Provider")
	}

	// 3. Core Infrastructure
	ui, err := guikit.New("ui.db", "ui.wal")
	if err != nil {
		log.Fatalf("Failed to boot guikit: %v", err)
	}

	// Pass the concrete provider here
	searchEngine, err := orchid_sync.NewEngine("data.db", 443, concreteProvider)
	if err != nil {
		log.Fatalf("Failed to boot search engine: %v", err)
	}

	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	// 4. Mandatory Router Dependencies
	r.GUIKit = ui
	// FIX: Mount to "/" so webauthnext and UI routes don't 404
	r.Mux.Handle("/", ui.Mux) 

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

	// 6. Bootstrap Flow
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

	// 7. Identity & Hardware Handshake
	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)
	gatewayAddress := "localhost:443"

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil {
		log.Fatalf("Mesh Node instantiation failed: %v", err)
	}

	// 8. Strict Auth Flow Bootstrap
	// FIX: Pass the concrete provider here to satisfy the compiler
	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, gatewayAddress)

	// Register identity routes
	identity_provider.RegisterRoutes(r, admin, audit, pe)

	// 9. User Logic Registration
	s := &Server{
		UI:           ui,
		AuthProvider: provider,
		SearchEngine: searchEngine,
		DB:           db,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
	}
	routeRegister(s)

	// 10. Execution
	log.Println("Booting Zero-Trust Edge Node on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
