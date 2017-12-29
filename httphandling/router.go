package httphandling

import (
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"net/http"
)

const (
	APIVersion = "v1"
)

type Route struct {
	Method         string
	Pattern        string
	Name           string
	Authentication bool
	HandlerFunc    http.HandlerFunc
}

func NewRouter(c *config.Config, stmtMap *database.StmtMap, fc *federationuser.FedUserCache) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	addRoutes(router, getFederationUserRoutes(c, stmtMap), c)
	addRoutes(router, getAssumeRoleRoutes(c, stmtMap, fc), c)
	addRoutes(router, getAccountClassRoutes(c, stmtMap), c)
	addRoutes(router, getAccountTypeRoutes(c, stmtMap), c)
	addRoutes(router, getAccountStatusRoutes(c, stmtMap), c)
	addRoutes(router, getRoleRoutes(c, stmtMap), c)
	addRoutes(router, getRoleMappingRoutes(c, stmtMap), c)

	return router
}

func addRoutes(router *mux.Router, routes []Route, c *config.Config) *mux.Router {
	for _, route := range routes {
		var handler http.Handler

		handler = route.HandlerFunc
		handler = WrapCommonHandler(handler, route.Authentication, c)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	return router
}
