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
)

type app struct {
	Router *mux.Router
	Config *config.Config
	FedUserCache *federationuser.FedUserCache
}

func (a *app) initialize(configPath string) {
	c, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to configure AWS Federation Server: %v\n", err)
	}
	a.Config = c
	c.ApplicationLogf(c.Summary())
	a.Router = httphandling.NewRouter(a.Config)
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
	// Run the app
	a.run()
}
