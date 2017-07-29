package httphandling

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/appcode"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/config"
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
				respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, fmt.Sprintf("Error accessing the vault: %v", err))
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
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, err.Error())
			return
		}
		if len(us) < 1 {
			respondGeneric(w, http.StatusNotFound, appcode.FEDERATIONUSER_UNKNOWN, "No federation users found.")
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
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, err.Error())
			return
		}
		if len(us) < 1 {
			respondGeneric(w, http.StatusNotFound, appcode.FEDERATIONUSER_UNKNOWN, "No federation users found.")
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
		u, err := loadFederationUser(c, a)
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

func updateFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := requestToARN(r)
		u, err := loadFederationUser(c, a)
		if err != nil {
			if _, is404 := err.(vaultclient.ErrSecretNotFound); is404 {
				respondGeneric(w, http.StatusNotFound, appcode.FEDERATIONUSER_UNKNOWN, "Federation user not found.")
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, err.Error())
			return
		}
		fu, err := processFederationUserPostData(r)
		if err != nil {
			respondGeneric(w, err.(ErrBadPostData).Code, appcode.BAD_DATA, err.Error())
			return
		}
		if a != fu.ARNString {
			respondGeneric(w, http.StatusConflict, appcode.BAD_DATA, "ARN in posted data does not match the API path")
			return
		}
		u.SetCredentials(fu.Credentials.AccessKeyID, fu.Credentials.SecretAccessKey, fu.Credentials.SessionToken, fu.Credentials.Expiration, fu.TTL, fu.MFASerialNumber, fu.MFASecret)
		err = u.Store()
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, fmt.Sprintf("Error storing federation user in vault: %v", err))
			return
		}
		respondGeneric(w, http.StatusOK, appcode.INFO_RESPONSE, fmt.Sprintf("Federation user %s updated.", u.ARNString))
		return
	})
}

func deleteFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := requestToARN(r)
		u, err := loadFederationUser(c, a)
		if err != nil {
			if _, is404 := err.(vaultclient.ErrSecretNotFound); is404 {
				respondGeneric(w, http.StatusNotFound, appcode.FEDERATIONUSER_UNKNOWN, "Federation user not found.")
				return
			}
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, err.Error())
			return
		}
		err = u.Delete()
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, err.Error())
			return
		}
		respondGeneric(w, http.StatusOK, appcode.INFO_RESPONSE, fmt.Sprintf("Federation user %s deleted.", u.ARNString))
		return
	})
}

func createFederationUserFunc(c *config.Config) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fu, err := processFederationUserPostData(r)
		if err != nil {
			respondGeneric(w, err.(ErrBadPostData).Code, appcode.BAD_DATA, err.Error())
			return
		}
		u, err := loadFederationUser(c, fu.ARNString)
		// Check that the federation user doesn't already exist
		if err == nil {
			respondGeneric(w, http.StatusConflict, appcode.FEDERATIONUSER_EXISTS, "Federation user already exists.")
			return
		}
		u.SetCredentials(fu.Credentials.AccessKeyID, fu.Credentials.SecretAccessKey, fu.Credentials.SessionToken, fu.Credentials.Expiration, fu.TTL, fu.MFASerialNumber, fu.MFASecret)
		err = u.Store()
		if err != nil {
			respondGeneric(w, http.StatusInternalServerError, appcode.FEDERATIONUSER_ERROR, fmt.Sprintf("Error storing federation user in vault: %v", err))
			return
		}
		respondGeneric(w, http.StatusOK, appcode.INFO_RESPONSE, fmt.Sprintf("Federation user %s created.", u.ARNString))
		return
	})
}

func getFederationUserRoutes(c *config.Config) []Route {
	return []Route{
		{
			Name:        "FederationUserAllList",
			Method:      "GET",
			Pattern:     fmt.Sprintf("/" + APIVersion + "/federationuser"),
			HandlerFunc: listAllFederationUserFunc(c),
		},
		{
			Name:        "FederationUserAccountList",
			Method:      "GET",
			Pattern:     fmt.Sprintf("/" + APIVersion + "/federationuser/arn:aws:iam::" + "{" + MuxVarAccountID + ":[0-9]{12}}:user"),
			HandlerFunc: listAccountFederationUserFunc(c),
		},
		{
			Name:        "FederationUserGet",
			Method:      "GET",
			Pattern:     fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc: getFederationUserFunc(c),
		},
		{
			Name:        "FederationUserUpdate",
			Method:      "PUT",
			Pattern:     fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc: updateFederationUserFunc(c),
		},
		{
			Name:        "FederationUserDelete",
			Method:      "DELETE",
			Pattern:     fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc: deleteFederationUserFunc(c),
		},
		{
			Name:        "FederationUserCreate",
			Method:      "POST",
			Pattern:     fmt.Sprintf("/" + APIVersion + "/federationuser"),
			HandlerFunc: createFederationUserFunc(c),
		},
		{
			Name:        "FederationUserCreateNotAllowed",
			Method:      "POST",
			Pattern:     fmt.Sprintf("/"+APIVersion+"/federationuser/"+federationuser.FedUserARNFormat, "{"+MuxVarAccountID+":[0-9]{12}}", "{"+MuxVarUsername+"}"),
			HandlerFunc: MethodNotAllowed(),
		},
	}
}

func requestToARN(r *http.Request) string {
	vars := mux.Vars(r)
	var accountID string = vars[MuxVarAccountID]
	var username string = vars[MuxVarUsername]
	return fmt.Sprintf(federationuser.FedUserARNFormat, accountID, username)
}

func loadFederationUser(c *config.Config, arn string) (federationuser.FederationUser, error) {
	u, err := federationuser.NewFederationUser(c, arn)
	if err != nil {
		return u, err
	}
	err = u.Load()
	return u, err
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
		return data, ErrBadPostData{}.Errorf("Could not parse data posted from client (%s) to %s : %v", r.RemoteAddr, r.RequestURI, err)
	}
	a, err := federationuser.ValidateFederationUserARN(data.ARNString)
	if err != nil {
		return data, ErrBadPostData{}.Errorf("Invalid Federation user ARN: %v", err)
	}
	data.ARN = a
	return data, nil
}
