package http

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/federationuser"
	"net/http"
)

const (
	MuxVarAccountID = "accountID"
	MuxVarUsername  = "username"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type Routes []Route

func NewRouter(routes Routes) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			HandlerFunc(route.HandlerFunc)
	}
	return router.
}

func Handler(c config.Config) http.Handler {
	var routes = Routes{
		Route{
			"FederationUserGet",
			"GET",
			fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			federationuser.GetFederationUser(),
		},
		Route{
			"FederationUserUpdate",
			"PUT",
			fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			handerfunchere,
		},
		Route{
			"FederationUserDelete",
			"DELETE",
			fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			handerfunchere,
		},
		Route{
			"FederationUserCreate",
			"POST",
			fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			handerfunchere,
		},
	}
	return NewRouter(routes)
}


