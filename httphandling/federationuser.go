package httphandling

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/errorcode"
	"github.com/jcmturner/awsfederation/federationuser"
	"net/http"
)

const (
	FedUserARNFormat = "arn:aws:iam::%s:user/%s"
	MuxVarAccountID  = "accountID"
	MuxVarUsername   = "username"
)

func GetFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var accountID string = vars["accountID"]
		var username string = vars["username"]
		arn := fmt.Sprintf(FedUserARNFormat, accountID, username)
		u, err := federationuser.NewFederationUser(c, arn)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, errorcode.TODO, err.Error())
			return
		}
		err = u.Load()
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, errorcode.TODO, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, u)
		return
	})
}

//func UpdateFederationUser(w http.ResponseWriter, r *http.Request) {
//}
//
//func DeleteFederationUser(w http.ResponseWriter, r *http.Request) {
//}
//
//func CreateFederationUser(w http.ResponseWriter, r *http.Request) {
//}
//
//func GetFederationUsers() (w http.ResponseWriter, r *http.Request) {
//}

func getFederationUserRoutes(c *config.Config) []Route {
	return []Route{
		{
			Name:        "FederationUserGet",
			Method:      "GET",
			Pattern:     fmt.Sprintf("/federationuser/"+FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc: GetFederationUserFunc(c),
		},
		//{
		//	Name: "FederationUserUpdate",
		//	Method: "PUT",
		//	fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
		//	HandlerFunc: handerfunchere,
		//},
		//{
		//	Name: "FederationUserDelete",
		//	Method: "DELETE",
		//	Pattern: fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
		//	HandlerFunc: handerfunchere,
		//},
		//{
		//	Name: "FederationUserCreate",
		//	Method: "POST",
		//	Pattern: fmt.Sprintf("/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
		//	HandlerFunc: handerfunchere,
		//},
	}
}
