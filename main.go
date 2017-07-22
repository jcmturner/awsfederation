package awsfederation

import (
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/httphandling"
	"net/http"
	"github.com/mgutz/logxi/v1"
)

type app struct {
	Router *mux.Router
	Config *config.Config
}

func (a *app) initialize() {
	//TODO load config

	a.Router = httphandling.NewRouter(a.Config)
}

func (a *app) run() {
	var err error
	//Start server
	if a.Config.Server.TLS.Enabled {
		err = http.ListenAndServeTLS(a.Config.Server.Socket, a.Config.Server.TLS.CertificateFile, a.Config.Server.TLS.KeyFile, a.Router)
	} else {
		err = http.ListenAndServe(a.Config.Server.Socket, a.Router)
	}
	log.Fatal(err)
}

func main() {
	//TODO read flags

	// Create the app
	var a app

	// Initialise the app
	a.initialize()

	// Run the app
	a.run()

}