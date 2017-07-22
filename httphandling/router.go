package httphandling

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/federationuser"
	"net/http"
)



type Route struct {
	Method      string
	Pattern     string
	Name        string
	HandlerFunc http.HandlerFunc
}

func NewRouter(c *config.Config) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	addRoutes(router, getFederationUserRoutes(c), c)

	return router
}

func addRoutes(router *mux.Router, routes []Route, c *config.Config) *mux.Router {
	for _, route := range routes {
		var handler http.Handler

		handler = route.HandlerFunc
		handler = WrapCommonHandler(handler, c)

		router.
		Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	return router
}

