package httphandling

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"io"
	"net/http"
)

const (
	MuxVarAccountID = "accountID"
)

type account struct {
	ID                string        `json:"ID"`
	Email             string        `json:"Type"`
	Name              string        `json:"Name"`
	Type              accountType   `json:"Type"`
	Status            accountStatus `json:"Status"`
	FederationUserARN string        `json:"FederationUserARN"`
}

type accountList struct {
	Accounts []account `json:"Accounts"`
}

func listAccountFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stmtKey := database.StmtKeyAcctSelectList
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for listing accounts not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		rows, err := stmt.Query()
		if err != nil {
			c.ApplicationLogf("error retrieving accounts from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		defer rows.Close()
		var as accountList
		for rows.Next() {
			var a account
			err := rows.Scan(&a.ID, &a.Email, &a.Name,
				&a.Type.ID, &a.Type.Type,
				&a.Type.Class.ID, &a.Type.Class.Class,
				&a.Status.ID, &a.Status.Status,
				&a.FederationUserARN,
			)
			if err != nil {
				c.ApplicationLogf("error processing rows of accounts from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			as.Accounts = append(as.Accounts, a)
		}
		respondWithJSON(w, http.StatusOK, as)
		return
	})
}

func getAccountFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := accountID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "account ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctSelect
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		var a account
		err := stmt.QueryRow(id).Scan(&a.ID, &a.Email, &a.Name,
			&a.Type.ID, &a.Type.Type,
			&a.Type.Class.ID, &a.Type.Class.Class,
			&a.Status.ID, &a.Status.Status,
			&a.FederationUserARN,
		)
		if err != nil {
			c.ApplicationLogf("error processing account from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, a)
		return
	})
}

func updateAccountFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i, ok := accountID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "account ID not in request")
			return
		}
		a, err := accountFromRequest(c, r)
		if err != nil || a.ID != i {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		stmtKey := database.StmtKeyAcctUpdate
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for updating an account not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Email, a.Name, a.Type.ID, a.Status.ID, a.FederationUserARN, i)
		if err != nil {
			c.ApplicationLogf("error executing database statement for updating account: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		if i, e := res.RowsAffected(); i != 1 || e != nil {
			c.ApplicationLogf("error unexpected result from database update of account: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account %s updated.", a.ID))
		return
	})
}

func createAccountFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := accountFromRequest(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		stmtKey := database.StmtKeyAcctInsert
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for creating an account not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.ID, a.Email, a.Name, a.Type.ID, a.Status.ID, a.FederationUserARN)
		if err != nil {
			c.ApplicationLogf("error executing database statement for creating account: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil || (i != 1 && i != 0) {
			c.ApplicationLogf("error unexpected result from database for creating account: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i == 0 {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountAlreadyExists, fmt.Sprintf("Account with ID %s already exists.", a.ID))
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account %s created.", a.ID))
		return
	})
}

func deleteAccountFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := accountID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "account ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctDelete
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for deleting an account not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(id)
		if err != nil {
			c.ApplicationLogf("error executing database statement for deleting account: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil {
			c.ApplicationLogf("error unexpected result from database for deleting account: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i != 1 {
			respondGeneric(w, http.StatusNotFound, appcodes.AccountUnknown, "Account ID not found.")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account with ID %s deleted.", id))
		return
	})
}

func getAccountRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "AccountAllList",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/account",
			HandlerFunc:    listAccountFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountGet",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/account/{" + MuxVarAccountID + ":[0-9]{12}}",
			HandlerFunc:    getAccountFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountUpdate",
			Method:         "PUT",
			Pattern:        "/" + APIVersion + "/account/{" + MuxVarAccountID + ":[0-9]{12}}",
			HandlerFunc:    updateAccountFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountDelete",
			Method:         "DELETE",
			Pattern:        "/" + APIVersion + "/account/{" + MuxVarAccountID + ":[0-9]{12}}",
			HandlerFunc:    deleteAccountFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountCreate",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/account",
			HandlerFunc:    createAccountFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountCreateNotAllowed",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/account/{" + MuxVarAccountID + ":[0-9]{12}}",
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func accountID(r *http.Request) (string, bool) {
	vars := mux.Vars(r)
	id, ok := vars[MuxVarAccountID]
	return id, ok
}

func accountFromRequest(c *config.Config, r *http.Request) (a account, err error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	err = dec.Decode(&a)
	if err != nil {
		c.ApplicationLogf("error dcoding provided JSON into account: %v", err)
	}
	return
}
