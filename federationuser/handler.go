package federationuser

import (
	"net/http"
	"github.com/gorilla/mux"
	"fmt"
	"github.com/jcmturner/awsfederation/config"
)

const(
	FedUserARNFormat = "arn:aws:iam::%s:user/%s"
)

func GetFederationUser(c *config.Config, w http.ResponseWriter, r *http.Request) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var accountID string = vars["accountID"]
		var username string = vars["username"]
		arn := fmt.Sprintf(FedUserARNFormat, accountID, username)
		u, err := NewFederationUser(c, arn)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}

	}


}

func handleSysLeader(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handleSysLeaderGet(core, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
		}
	})
}

func UpdateFederationUser(w http.ResponseWriter, r *http.Request) {
}

func DeleteFederationUser(w http.ResponseWriter, r *http.Request) {
}

func CreateFederationUser(w http.ResponseWriter, r *http.Request) {
}

func GetFederationUsers() (w http.ResponseWriter, r *http.Request) {
}
