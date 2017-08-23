package httphandling

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/appcode"
	"github.com/jcmturner/awsfederation/apperrors"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/vaultclient"
	"io"
	"net/http"
)

const (
	MuxVarAccountID = "accountID"
	MuxVarUsername  = "username"
)

func listAllFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		al := []string{}
		qv := r.URL.Query()
		if as, ok := qv["account"]; ok {
			al = as
		} else {
			cl, err := vaultclient.NewClient(c.Vault.Config, c.Vault.Credentials)
			if err != nil {
				respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, fmt.Sprintf("Error accessing the vault: %v", err))
				return
			}
			m, err := cl.List("")
			if m != nil {
				keys := m["keys"].([]interface{})
				for _, v := range keys {
					a, err := arn.Parse(v.(string))
					if err == nil {
						al = append(al, a.AccountID)
					}
				}
			}
		}
		us, err := getListIAMUsers(c, al)
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, err.Error())
			return
		}
		if len(us) < 1 {
			respondGeneric(w, http.StatusNotFound, appcode.FederationUserUnknown, "No federation users found.")
			return
		}
		ul := federationuser.FederationUserList{
			FederationUsers: us,
		}
		respondWithJSON(w, http.StatusOK, ul)
		return
	})
}

func listAccountFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		var accountID string = vars[MuxVarAccountID]
		us, err := getListIAMUsers(c, []string{accountID})
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, err.Error())
			return
		}
		if len(us) < 1 {
			respondGeneric(w, http.StatusNotFound, appcode.FederationUserUnknown, "No federation users found.")
			return
		}
		ul := federationuser.FederationUserList{
			FederationUsers: us,
		}
		respondWithJSON(w, http.StatusOK, ul)
		return
	})
}

func getFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := requestToARN(r)
		u, err := federationuser.LoadFederationUser(c, a)
		if err != nil {
			if _, is404 := err.(vaultclient.ErrSecretNotFound); is404 {
				respondGeneric(w, http.StatusNotFound, appcode.FederationUserUnknown, "Federation user not found.")
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, u)
		return
	})
}

func updateFederationUserFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := requestToARN(r)
		u, err := federationuser.LoadFederationUser(c, a)
		if err != nil {
			if _, is404 := err.(vaultclient.ErrSecretNotFound); is404 {
				respondGeneric(w, http.StatusNotFound, appcode.FederationUserUnknown, "Federation user not found.")
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, err.Error())
			return
		}
		fu, err := processFederationUserPostData(r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcode.BadData, err.Error())
			return
		}
		if a != fu.ARNString {
			respondGeneric(w, http.StatusConflict, appcode.BadData, "ARN in posted data does not match the API path")
			return
		}
		u.SetCredentials(fu.Credentials.AccessKeyID, fu.Credentials.SecretAccessKey, fu.Credentials.SessionToken, fu.Credentials.Expiration, fu.TTL, fu.MFASerialNumber, fu.MFASecret)
		err = u.Store(*stmtMap)
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, fmt.Sprintf("Error storing federation user in vault: %v", err))
			return
		}
		respondGeneric(w, http.StatusOK, appcode.Info, fmt.Sprintf("Federation user %s updated.", u.ARNString))
		return
	})
}

func deleteFederationUserFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := requestToARN(r)
		u, err := federationuser.LoadFederationUser(c, a)
		if err != nil {
			if _, is404 := err.(vaultclient.ErrSecretNotFound); is404 {
				respondGeneric(w, http.StatusNotFound, appcode.FederationUserUnknown, "Federation user not found.")
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, err.Error())
			return
		}
		err = u.Delete(*stmtMap)
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, err.Error())
			return
		}
		respondGeneric(w, http.StatusOK, appcode.Info, fmt.Sprintf("Federation user %s deleted.", u.ARNString))
		return
	})
}

func createFederationUserFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fu, err := processFederationUserPostData(r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcode.BadData, err.Error())
			return
		}
		u, err := federationuser.LoadFederationUser(c, fu.ARNString)
		// Check that the federation user doesn't already exist
		if err == nil {
			respondGeneric(w, http.StatusConflict, appcode.FederationUserAlreadyExists, "Federation user already exists.")
			return
		}
		u.SetCredentials(fu.Credentials.AccessKeyID, fu.Credentials.SecretAccessKey, fu.Credentials.SessionToken, fu.Credentials.Expiration, fu.TTL, fu.MFASerialNumber, fu.MFASecret)
		err = u.Store(*stmtMap)
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FederationUserError, fmt.Sprintf("Error storing federation user in vault: %v", err))
			return
		}
		respondGeneric(w, http.StatusOK, appcode.Info, fmt.Sprintf("Federation user %s created.", u.ARNString))
		return
	})
}

func getFederationUserRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "FederationUserAllList",
			Method:         "GET",
			Pattern:        fmt.Sprintf("/" + APIVersion + "/federationuser"),
			HandlerFunc:    listAllFederationUserFunc(c),
			Authentication: true,
		},
		{
			Name:           "FederationUserAccountList",
			Method:         "GET",
			Pattern:        fmt.Sprintf("/" + APIVersion + "/federationuser/arn:aws:iam::" + "{" + MuxVarAccountID + ":[0-9]{12}}:user"),
			HandlerFunc:    listAccountFederationUserFunc(c),
			Authentication: true,
		},
		{
			Name:           "FederationUserGet",
			Method:         "GET",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc:    getFederationUserFunc(c),
			Authentication: true,
		},
		{
			Name:           "FederationUserUpdate",
			Method:         "PUT",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc:    updateFederationUserFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "FederationUserDelete",
			Method:         "DELETE",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc:    deleteFederationUserFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "FederationUserCreate",
			Method:         "POST",
			Pattern:        fmt.Sprintf("/" + APIVersion + "/federationuser"),
			HandlerFunc:    createFederationUserFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "FederationUserCreateNotAllowed",
			Method:         "POST",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func requestToARN(r *http.Request) string {
	vars := mux.Vars(r)
	var accountID string = vars[MuxVarAccountID]
	var username string = vars[MuxVarUsername]
	return fmt.Sprintf(federationuser.FedUserARNFormat, accountID, username)
}

func getListIAMUsers(c *config.Config, accountIDs []string) ([]string, error) {
	var iamUsers []string
	for _, accountID := range accountIDs {
		iamUserPath := fmt.Sprintf(federationuser.FedUserARNFormat, accountID, "")
		cl, err := vaultclient.NewClient(c.Vault.Config, c.Vault.Credentials)
		if err != nil {
			return iamUsers, err
		}
		m, _ := cl.List(iamUserPath)
		if m != nil {
			keys := m["keys"].([]interface{})
			for _, v := range keys {
				iamUsers = append(iamUsers, fmt.Sprintf(federationuser.FedUserARNFormat, accountID, v.(string)))
			}
		}
	}
	return iamUsers, nil
}

func processFederationUserPostData(r *http.Request) (federationuser.FederationUser, error) {
	var data federationuser.FederationUser
	//Set limit to reading 1MB. Probably a bit large. Prevents DOS by posting large amount of data
	dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
	defer r.Body.Close()
	err := dec.Decode(&data)
	if err != nil {
		return data, apperrors.ErrBadPostData{}.Errorf("Could not parse data posted from client (%s) to %s : %v", r.RemoteAddr, r.RequestURI, err)
	}
	a, err := federationuser.ValidateFederationUserARN(data.ARNString)
	if err != nil {
		return data, apperrors.ErrBadPostData{}.Errorf("Invalid Federation user ARN: %v", err)
	}
	data.ARN = a
	return data, nil
}
