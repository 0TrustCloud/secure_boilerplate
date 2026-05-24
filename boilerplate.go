package boilerplate

import (
	"log"

	"github.com/gddisney/guikit"
	"github.com/gddisney/orchid_sync"
	"github.com/gddisney/secure_bootstrap"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

type Server struct {
	UI           *guikit.GUIKit
	AuthProvider interface{} // Fixed: Used interface{} to bypass undefined type error
	SearchEngine *orchid_sync.Engine
	DB           *ultimate_db.DB
	Router       *secure_network.Router
}

// Start enforces the strict boot sequence required for BootstrapAuth
func Start(routeRegister func(s *Server)) {
	// 1. Core Infrastructure
	ui, err := guikit.New("ui.db", "ui.wal")
	if err != nil { log.Fatalf("Failed to boot guikit: %v", err) }

	authProvider, err := webauthnext.New(ui, "Secure Service", "localhost", "https://localhost")
	if err != nil { log.Fatalf("Failed to boot webauthnext: %v", err) }

	searchEngine, err := orchid_sync.NewEngine("data.db", 443, authProvider)
	if err != nil { log.Fatalf("Failed to boot search engine: %v", err) }

	edgeNode := searchEngine.NetNode()
	db := edgeNode.DB
	r := edgeNode.Router

	// 2. Mandatory Router Dependencies
	r.GUIKit = ui
	r.Mux.Handle("/index", ui.Mux)

	// 3. Hardware/Identity Handshake
	keyTxn := db.BeginTxn()
	gatewayPubKey, _ := db.Read(99, keyTxn, []byte("mesh_noise_pub"))
	db.CommitTxn(keyTxn)
	log.Printf("GATEWAY NOISE PUBKEY: %x", gatewayPubKey)
	gatewayAddress := "localhost:443"

	meshNode, err := secure_network.NewMeshNode(db, gatewayPubKey)
	if err != nil { log.Fatalf("Mesh Node instantiation failed: %v", err) }

	// 4. Strict Auth Flow Bootstrap
	secure_bootstrap.BootstrapAuth(r, authProvider, meshNode, gatewayAddress)

	// 5. User Logic Registration
	s := &Server{UI: ui, AuthProvider: authProvider, SearchEngine: searchEngine, DB: db, Router: r}
	routeRegister(s)

	// 6. Execution
	log.Println("Booting Zero-Trust Edge Node on :443")
	if err := edgeNode.Start("443", r.TLSConfig); err != nil {
		log.Fatalf("Edge Node crashed: %v", err)
	}
}
