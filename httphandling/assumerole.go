package httphandling

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/assumerole"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"net/http"
)

const (
	MuxVarRoleUUID = "roleUUID"
)

func getAssumeRoleFunc(c *config.Config, stmtMap *database.StmtMap, fc *federationuser.FedUserCache) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleID := requestToRoleUUID(r)
		u, err := GetIdentity(r.Context())
		if err != nil {
			respondUnauthorized(w, c)
			return
		}
		o, err := assumerole.Federate(u, roleID, *stmtMap, fc, c)
		if err != nil {
			if e, NotAuthz := err.(appcodes.ErrUnauthorized); NotAuthz {
				respondGeneric(w, http.StatusUnauthorized, e.AppCode, e.Error())
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcodes.AssumeRoleError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, o)
		return
	})
}

func getAssumeRoleRoutes(c *config.Config, stmtMap *database.StmtMap, fc *federationuser.FedUserCache) []Route {
	return []Route{
		{
			Name:           "AssumeRoleGet",
			Method:         "GET",
			Pattern:        fmt.Sprintf(`/%s/assumerole/{%s}:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}`, APIVersion, MuxVarRoleUUID),
			HandlerFunc:    getAssumeRoleFunc(c, stmtMap, fc),
			Authentication: true,
		},
	}
}

func requestToRoleUUID(r *http.Request) string {
	vars := mux.Vars(r)
	return vars[MuxVarRoleUUID]
}
