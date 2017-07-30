package awsfederation

import (
	"flag"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/httphandling"
	"log"
	"net/http"
	"github.com/jcmturner/awsfederation/federationuser"
	"fmt"
	"os"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jcmturner/vaultclient"
	"strings"
	"github.com/jcmturner/awsfederation/database"
)

type app struct {
	Router *mux.Router
	Config *config.Config
	FedUserCache *federationuser.FedUserCache
	DB *sql.DB
	PreparedStmts *database.StmtMap
}

func (a *app) initialize(configPath string) {
	// Load configuration
	c, err := config.Load(configPath)
	if err != nil {
		c.ApplicationLogf("Failed to configure AWS Federation Server: %v", err)
		log.Fatalf("Failed to configure AWS Federation Server: %v\n", err)
	}
	a.Config = c
	c.ApplicationLogf(c.Summary())

	// Initialise the HTTP router
	a.Router = httphandling.NewRouter(a.Config)

	// Set up the database connection
	dbs := c.Database.ConnectionString
	vc, err := vaultclient.NewClient(*c.Vault.Config, *c.Vault.Credentials)
	dbm, err := vc.Read(c.Database.CredentialsVaultPath)
	if err != nil {
		c.ApplicationLogf("Failed to load database credentials from the vault: %v", err)
		log.Fatalf("Failed to load database credentials from the vault: %v\n", err)
	}
	if v, ok := dbm["username"]; ok {
		dbs = strings.Replace(dbs, "${username}", v.(string), -1)
	}
	if v, ok := dbm["password"]; ok {
		dbs = strings.Replace(dbs, "${password}", v.(string), -1)
	}
	a.DB, err = sql.Open(c.Database.DriverName, dbs)
	if err != nil {
		c.ApplicationLogf("Failed to open database: %v\n", err)
		log.Fatalf("Failed to open database: %v\n", err)
	}
	if err := a.DB.Ping(); err != nil {
		c.ApplicationLogf("Database connection test failed: %v\n", err)
		log.Fatalf("Database connection test failed: %v\n", err)
	}

	// Prepare and store DB statements
	a.PreparedStmts, err = database.NewStmtMap(a.DB)
}

func (a *app) run() {
	fmt.Fprintln(os.Stderr, a.Config.Summary())
	var err error
	//Start server
	if a.Config.Server.TLS.Enabled {
		err = http.ListenAndServeTLS(a.Config.Server.Socket, a.Config.Server.TLS.CertificateFile, a.Config.Server.TLS.KeyFile, a.Router)
	} else {
		err = http.ListenAndServe(a.Config.Server.Socket, a.Router)
	}
	log.Fatalln(err)
}

func main() {
	configPath := flag.String("config", "./awsfederation-config.json", "Specify the path to the configuration file")
	// Create the app
	var a app
	// Initialise the app
	a.initialize(*configPath)
	//
	defer a.DB.Close()
	// Run the app
	a.run()
}
