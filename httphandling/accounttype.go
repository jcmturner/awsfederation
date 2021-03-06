package httphandling

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"io"
	"net/http"
	"strconv"
)

const (
	MuxVarAccountTypeID = "accountTypeID"
	AccountTypeAPI      = "accounttype"
	AccountTypeGETTmpl  = "{\"ID\":%d,\"Type\":\"%s\",\"Class\":{\"ID\":%d}}"
	AccountTypePOSTTmpl = "{\"Type\":\"%s\",\"Class\":{\"ID\":%d}}"
	AccountTypePUTTmpl  = "{\"ID\":%d,\"Type\":\"%s\",\"Class\":{\"ID\":%d}}"
)

type accountType struct {
	ID    int          `json:"ID,omitempty"`
	Type  string       `json:"Type"`
	Class accountClass `json:"Class,omitempty"`
}

type accountTypeList struct {
	AccountTypes []accountType `json:"AccountTypes"`
}

func listAccountTypeFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stmtKey := database.StmtKeyAcctTypeSelectList
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for listing account types not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		rows, err := stmt.Query()
		if err != nil {
			c.ApplicationLogf("error retrieving account types from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		defer rows.Close()
		var as accountTypeList
		for rows.Next() {
			var a accountType
			err := rows.Scan(&a.ID, &a.Type, &a.Class.ID)
			if err != nil {
				c.ApplicationLogf("error processing rows of account types from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			as.AccountTypes = append(as.AccountTypes, a)
		}
		respondWithJSON(w, http.StatusOK, as)
		return
	})
}

func getAccountTypeFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, id, ok := accountTypeID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "type ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctTypeSelect
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account types not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		var a accountType
		err := stmt.QueryRow(id).Scan(&a.ID, &a.Type, &a.Class.ID)
		if err != nil {
			c.ApplicationLogf("error processing account type from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, a)
		return
	})
}

func updateAccountTypeFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, i, ok := accountTypeID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "type ID not in request")
			return
		}
		a, err := accountTypeFromRequest(c, r)
		if err != nil || a.ID != i {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		stmtKey := database.StmtKeyAcctTypeUpdate
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for updating an account type not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Type, a.ID, a.Class.ID)
		if err != nil {
			c.ApplicationLogf("error executing database statement for updating account Type: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		if i, e := res.RowsAffected(); i != 1 || e != nil {
			c.ApplicationLogf("error unexpected result from database update of account type: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account Type %d updated.", a.ID))
		return
	})
}

func createAccountTypeFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := accountTypeFromRequest(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}

		// Check it does not already exist
		stmtKey := database.StmtKeyAcctTypeByName
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account type by name not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		err = stmt.QueryRow(a.Type).Scan()
		if err != sql.ErrNoRows {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountTypeAlreadyExists, fmt.Sprintf("Account Type with name %s already exists.", a.Type))
			return
		}

		stmtKey = database.StmtKeyAcctTypeInsert
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for creating an account type not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt = (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Type, a.Class.ID)
		if err != nil {
			c.ApplicationLogf("error executing database statement for creating account type: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil || (i != 1 && i != 0) {
			c.ApplicationLogf("error unexpected result from database for creating account type: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i == 0 {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountTypeAlreadyExists, fmt.Sprintf("Account Type with name %s already exists.", a.Type))
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account Type %s created.", a.Type))
		return
	})
}

func deleteAccountTypeFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, id, ok := accountTypeID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "account type ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctTypeDelete
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for deleting an account Type not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(id)
		if err != nil {
			c.ApplicationLogf("error executing database statement for deleting account Type: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil {
			c.ApplicationLogf("error unexpected result from database for deleting account type: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i != 1 {
			respondGeneric(w, http.StatusNotFound, appcodes.AccountTypeUnknown, "Account Type ID not found.")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account Type with ID %d deleted.", id))
		return
	})
}

func getAccountTypeRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "AccountTypeAllList",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/accounttype",
			HandlerFunc:    listAccountTypeFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountTypeGet",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/accounttype/{" + MuxVarAccountTypeID + ":[0-9]+}",
			HandlerFunc:    getAccountTypeFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountTypeUpdate",
			Method:         "PUT",
			Pattern:        "/" + APIVersion + "/accounttype/{" + MuxVarAccountTypeID + ":[0-9]+}",
			HandlerFunc:    updateAccountTypeFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountTypeDelete",
			Method:         "DELETE",
			Pattern:        "/" + APIVersion + "/accounttype/{" + MuxVarAccountTypeID + ":[0-9]+}",
			HandlerFunc:    deleteAccountTypeFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountTypeCreate",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/accounttype",
			HandlerFunc:    createAccountTypeFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountTypeCreateNotAllowed",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/accounttype/{" + MuxVarAccountTypeID + ":[0-9]+}",
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func accountTypeID(r *http.Request) (string, int, bool) {
	vars := mux.Vars(r)
	id, ok := vars[MuxVarAccountTypeID]
	i, err := strconv.Atoi(id)
	if err != nil {
		return id, 0, false
	}
	return id, i, ok
}

func accountTypeFromRequest(c *config.Config, r *http.Request) (a accountType, err error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	err = dec.Decode(&a)
	if err != nil {
		c.ApplicationLogf("error decoding provided JSON into accountType: %v", err)
	}
	return
}
