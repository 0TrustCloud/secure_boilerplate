package secure_bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"os"

	"github.com/gddisney/guikit"
	"github.com/gddisney/identity_provider"
	"github.com/gddisney/orchid_sync"
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

var legacySessionManager *secure_policy.SessionManager

func Start(configPath string, provider IdentityProvider, routeRegister func(s *Server)) {
	cfgData, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	ui, err := guikit.New("ui.db", "ui.wal")
	if err != nil {
		log.Fatalf("Failed to boot guikit: %v", err)
	}

	searchEngine, err := orchid_sync.NewEngine("data.db", 443, provider.(*webauthnext.Provider))
	if err != nil {
		log.Fatalf("Failed to boot search engine: %v", err)
	}

	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	bus := make(chan secure_network.SystemEvent, 10)
	pe := secure_policy.NewPolicyEngine(db)

	jwtSigningKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate JWT signing key: %v", err)
	}
	legacySessionManager = secure_policy.NewSessionManager(db, jwtSigningKey)

	admin := &identity_provider.AdminController{
		DB:           db,
		PolicyEngine: pe,
		LocalBus:     bus,
	}

	audit := identity_provider.NewAuditController(db, searchEngine, ui)
	scim := identity_provider.NewSCIMDaemon(db, bus)

	go scim.Start()

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

	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)
	gatewayAddress := "localhost:443"

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil {
		log.Fatalf("Mesh Node instantiation failed: %v", err)
	}

	// FIX: Package prefix removed so it references the function below natively
	BootstrapAuth(r, provider, meshNode, gatewayAddress)

	// FIX: legacySessionManager added as the 5th argument
	identity_provider.RegisterRoutes(r, admin, audit, pe, legacySessionManager)

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

	log.Println("Booting Zero-Trust Edge Node on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}

func BootstrapAuth(router *secure_network.Router, provider IdentityProvider, node *secure_network.MeshNode, address string) {
	// Implement connection setup tasks here
}

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sub := r.Header.Get("X-Secure-Subject"); sub != "" {
			next.ServeHTTP(w, r)
			return
		}

		if legacySessionManager == nil {
			http.Redirect(w, r, "/bootstrap", http.StatusFound)
			return
		}

		cookie, err := r.Cookie("secure_mesh_session")
		if err != nil {
			http.Redirect(w, r, "/bootstrap", http.StatusFound)
			return
		}

		_, err = legacySessionManager.ValidateCookieToken(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/bootstrap", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "secure_mesh_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/bootstrap", http.StatusFound)
}
