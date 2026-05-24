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

// --- Cryptographic UI Middleware to replace legacy secure_bootstrap ---

func RequireJWT(sm *secure_policy.SessionManager, next func(*guikit.Context)) func(*guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(c.W, c.R, "/login", http.StatusFound)
			return
		}

		subjectID, err := sm.ValidateCookieToken(cookie.Value)
		if err != nil {
			http.SetCookie(c.W, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
			http.Redirect(c.W, c.R, "/login", http.StatusFound)
			return
		}
		
		c.Data["SubjectID"] = subjectID
		next(c)
	}
}

func RequirePolicy(pe *secure_policy.PolicyEngine, sm *secure_policy.SessionManager, action, resource string, next func(*guikit.Context)) func(*guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil {
			http.Redirect(c.W, c.R, "/login", http.StatusFound)
			return
		}

		subjectID, err := sm.ValidateCookieToken(cookie.Value)
		if err != nil {
			http.SetCookie(c.W, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
			http.Redirect(c.W, c.R, "/login", http.StatusFound)
			return
		}

		if !pe.Evaluate([]byte(subjectID), action, resource, map[string]string{}) {
			c.W.WriteHeader(http.StatusForbidden)
			c.W.Write([]byte("Forbidden by Zero-Trust Policy"))
			return
		}

		c.Data["SubjectID"] = subjectID
		next(c)
	}
}

func HandleLogout(sm *secure_policy.SessionManager) func(*guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err == nil && cookie.Value != "" {
			sm.RevokeTokenString(cookie.Value)
		}
		http.SetCookie(c.W, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(c.W, c.R, "/login", http.StatusFound)
	}
}

// ------------------------------------------------------------------

func Start(ui *guikit.GUIKit, configPath string, provider IdentityProvider, routeRegister func(s *Server), gateway string) {
	var cfg Config
	if cfgData, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
	} else {
		log.Printf("[WARNING] Bootstrap config not found at %s. Skipping YAML load.", configPath)
	}

	concreteProvider, ok := provider.(*webauthnext.Provider)
	if !ok { log.Fatalf("FATAL: Provided IdentityProvider is not a *webauthnext.Provider") }

	searchEngine, err := orchid_sync.NewEngine("iam_data.db", 443, concreteProvider)
	if err != nil { log.Fatalf("Failed to boot search engine: %v", err) }

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
	gatewayAddress := gateway

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil { log.Fatalf("Mesh Node instantiation failed: %v", err) }

	secure_bootstrap.BootstrapAuth(r, concreteProvider, meshNode, gatewayAddress)
	identity_provider.RegisterRoutes(r, admin, audit, pe, concreteProvider.SessionManager)

	s := &Server{UI: ui, AuthProvider: provider, SearchEngine: searchEngine, DB: db, Router: r, Admin: admin, Audit: audit}

	if r.GUIKit != nil {
		r.GUIKit.Get("/logout", HandleLogout(concreteProvider.SessionManager))
		
		// SWAPPED secure_bootstrap for RequireJWT
		r.GUIKit.Get("/", RequireJWT(concreteProvider.SessionManager, func(c *guikit.Context) {
			c.Data["Title"] = "Identity Dashboard"
			r.GUIKit.Render(c, "views/portal")
		}))
	}

	routeRegister(s)

	log.Println("Booting Zero-Trust Identity Hub on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
