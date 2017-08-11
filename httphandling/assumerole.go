package httphandling

import (
	"fmt"
	"github.com/jcmturner/awsfederation/appcode"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/vaultclient"
	"net/http"
)

func getAssumeRoleFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := requestToARN(r)

		// TODO authorization check that user should have access to this role. Authorization check should also get the duration and policy authorized for this user. If the user if authorised by more than one
		// TODO resolve which federation user to use for this

		u, err := federationuser.LoadFederationUser(c, a)
		if err != nil {
			if _, is404 := err.(vaultclient.ErrSecretNotFound); is404 {
				respondGeneric(w, http.StatusNotFound, appcode.FEDERATIONUSER_UNKNOWN, "Federation user not found.")
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, u)
		return
	})
}

func getAssumeRoleRoutes(c *config.Config) []Route {
	return []Route{
		{
			Name:        "AssumeRoleGet",
			Method:      "GET",
			Pattern:     fmt.Sprintf("/"+APIVersion+"/assumerole/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc: getFederationUserFunc(c),
		},
	}
}
