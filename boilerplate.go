package secure_boilerplate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/identity_provider"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/orchid_sync"
	"github.com/0TrustCloud/secure_bootstrap"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/mesh_client"
	"github.com/0TrustCloud/secure_k8s"
	"github.com/0TrustCloud/secure_network"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/secure_ssh"
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
	AdminAccess secure_bootstrap.AdminAccessConfig `yaml:"admin_access"`
	Server      struct {
		ServiceName string `yaml:"service_name"`
		Host        string `yaml:"host"`
		Domain      string `yaml:"domain"`
		Port        string `yaml:"port"`
		QuicPort    string `yaml:"quic_port"`
		HTTPOnly    bool   `yaml:"http_only"`
		ACME        struct {
			Email    string `yaml:"email"`
			CacheDir string `yaml:"cache_dir"`
			Staging  bool   `yaml:"staging"`
		} `yaml:"acme"`
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
	AdminAccess  secure_bootstrap.AdminAccessConfig
	SSHClient    *secure_ssh.Client
	K8sClient    *secure_k8s.Client
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

func (rm *RouteModule) Admin(pattern string, handler http.HandlerFunc) {
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
				secure_bootstrap.RequireAdmin(rm.Server.Router, rm.Server.AdminAccess, protected)(c)
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

	db := ui.DB 

	jwtSigningKey, err := loadOrCreateSessionSigningKey()
	if err != nil {
		log.Fatalf("Failed loading session signing key: %v", err)
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

	sessionManager := secure_policy.NewSessionManager(sdfEngine, &jwtSigningKey.PublicKey)

	realProvider, err := webauthnext.New(ui, sessionManager, sdfEngine, serviceName, cfg.Server.Host, cfg.Server.Domain, "0trust.services")
	if err != nil {
		log.Fatalf("Failed to execute native provider constructor: %v", err)
	}

	if inputPtr, ok := provider.(*webauthnext.Provider); ok && inputPtr != nil {
		inputPtr.SessionManager = realProvider.SessionManager
		realProvider.InheritPreLaunchConfig(inputPtr)
	}

	sysLogger, err := logger.NewLogDispatcher(serviceName, 1000, sdfEngine)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	realProvider.Logger = sysLogger
	// Universal admin is always bootstrap-protected (YubiKey-pinned), every host.
	realProvider.AllowBootstrapRegistration("admin")
	for _, user := range cfg.Users {
		realProvider.AllowBootstrapRegistration(user.Subject)
	}

	skm := service_keys.NewServiceKeyManager(sdfEngine, realProvider, sysLogger)
	pe := secure_policy.NewPolicyEngine(sdfEngine)

	var rbacCfg RBACConfig
	if cfg.Files.RbacPath != "" {
		if rbacData, err := os.ReadFile(cfg.Files.RbacPath); err == nil {
			if yaml.Unmarshal(rbacData, &rbacCfg) == nil {
				for _, role := range rbacCfg.Roles {
					for _, perm := range role.Permissions {
						_ = pe.GrantPermission([]byte(role.Name), perm)
					}
					_ = pe.GrantPermission([]byte(role.Name), "role:"+role.Name)
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

	acmeDomain := cfg.Server.Host
	if acmeDomain == "" {
		acmeDomain = "0trust.cloud"
	}
	r, err := secure_network.NewRouter(
		sdfEngine,
		ui,
		"session_id",
		pe,
		sessionManager,
		sysLogger,
		secure_network.WithACME(secure_network.ACMEConfig{
			Email:    cfg.Server.ACME.Email,
			CacheDir: cfg.Server.ACME.CacheDir,
			Domain:   acmeDomain,
			Staging:  cfg.Server.ACME.Staging,
		}),
		secure_network.WithHTTPOnly(cfg.Server.HTTPOnly),
	)
	if err != nil {
		log.Fatalf("Failed to initialize Router: %v", err)
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

	_, sshClient := secure_ssh.Install(r, meshNode, pe)
	_, k8sClient := secure_k8s.Install(r, meshNode, pe)
	_ = mesh_client.GrantMeshPeer(pe, meshNode.GetNoisePubKey())

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

	adminAccess := cfg.AdminAccess
	if len(adminAccess.AllowedSubjects) == 0 && len(adminAccess.AllowedIPs) == 0 {
		adminAccess = secure_bootstrap.DefaultAdminAccess()
	}
	// Force hash 8c6976e5… + pinned YubiKeys on every face (social.0trust.cloud included).
	adminAccess = secure_bootstrap.MergeAdminAccessDefaults(adminAccess)
	if !adminAccess.BreakglassLocalhost {
		adminAccess.BreakglassLocalhost = true
	}
	realProvider.SetAdminPin(webauthnext.AdminPinConfig{
		PinnedCredentialIDs: adminAccess.PinnedCredentialIDs,
		BreakglassLocalhost: adminAccess.BreakglassLocalhost,
	})
	log.Printf("[admin] universal admin hash=%s pinned_credentials=%d (login accepts registered keys; pin on register only)",
		secure_bootstrap.AdminSubjectHash[:12]+"…", len(adminAccess.PinnedCredentialIDs))

	for _, user := range cfg.Users {
		subject := strings.TrimSpace(user.Subject)
		if subject != "" {
			grantRole := func(roleName string) {
				for _, role := range rbacCfg.Roles {
					if !strings.EqualFold(role.Name, roleName) {
						continue
					}
					for _, perm := range role.Permissions {
						_ = pe.GrantPermission([]byte(subject), perm)
					}
					_ = pe.GrantPermission([]byte(subject), "role:"+role.Name)
				}
			}
			if secure_bootstrap.SubjectAllowed(adminAccess, subject) {
				grantRole("admin")
			}
			grantRole(subject)
		}
		for _, app := range cfg.Apps {
			if app.ID != "" {
				_ = admin.AssignUserToApp(user, app.ID, "system_bootstrap")
			}
		}
		if user.SessionID != "" {
			_ = admin.AssignUserToApp(user, user.SessionID, "system_bootstrap")
		}
	}

	listenPort := cfg.Server.Port
	if listenPort == "" {
		listenPort = "443"
	}
	hostAddr := cfg.Server.Host + ":" + listenPort
	if cfg.Server.Host == "" {
		hostAddr = "0trust.cloud:" + listenPort
	}
	
	// Agnostic Target Resolution: Find the view explicitly tagged as 'index'
	targetURL := ""
	for _, view := range cfg.Views {
		if view.Name == "index" {
			targetURL = view.Path
			break
		}
	}

	_ = realProvider.InitSAMLn(db, cfg.Server.Domain, 1)
	secure_bootstrap.BootstrapAuth(r, db, realProvider, meshNode, hostAddr, sysLogger)

	identity_provider.RegisterRoutes(r, admin, audit, pe, sessionManager, sysLogger, configPath)

	s := &Server{
		UI:           ui,
		AuthProvider: realProvider,
		SearchEngine: searchEngine,
		DB:           db,
		Router:       r,
		Admin:        admin,
		Audit:        audit,
		Logger:       sysLogger,
		MeshNode:     meshNode,
		ServiceKeys:  skm,
		AdminAccess:  adminAccess,
		SSHClient:    sshClient,
		K8sClient:    k8sClient,
	}

	if ui != nil {
		r.Mux.HandleFunc("GET /logout", func(w http.ResponseWriter, req *http.Request) {
			secure_bootstrap.HandleLogout(w, req)
		})

		// Post-login gateway: authenticated users land on /index, then route to the YAML index view.
		landingURL := targetURL
		if landingURL == "" {
			landingURL = "/dashboard"
		}
		r.Mux.HandleFunc("GET /index", func(w http.ResponseWriter, req *http.Request) {
			c := &guikit.Context{W: w, R: req, Data: make(map[string]interface{})}
			secure_bootstrap.RequireAuth(r, func(ctx *guikit.Context) {
				user, _ := secure_bootstrap.SessionUser(ctx.R, r)
				target := landingURL
				if !secure_bootstrap.IsAdminAccess(adminAccess, user, secure_bootstrap.ClientIP(ctx.R)) {
					target = "/apps"
				}
				http.Redirect(ctx.W, ctx.R, target, http.StatusFound)
			})(c)
		})
		r.Mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/index", http.StatusFound)
		})
	}

	routeRegister(&RouteModule{Server: s, Views: cfg.Views})

	log.Printf("Booting Zero-Trust Identity Hub on %s", hostAddr)
	r.Port = listenPort
	r.QuicPort = cfg.Server.QuicPort
	if r.QuicPort == "" {
		r.QuicPort = "443"
	}
	go r.Boot() 

	return &PlatformControl{Router: r}
}

func loadOrCreateSessionSigningKey() (*rsa.PrivateKey, error) {
	dataDir := os.Getenv("TRUST_DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}
	keyPath := filepath.Join(dataDir, "session-signing.pem")
	if raw, err := os.ReadFile(keyPath); err == nil && len(raw) > 0 {
		if key, err := x509.ParsePKCS1PrivateKey(raw); err == nil {
			return key, nil
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return key, nil
	}
	_ = os.WriteFile(keyPath, x509.MarshalPKCS1PrivateKey(key), 0o600)
	return key, nil
}
