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
	MuxVarAccountClassID = "accountClassID"
	AccountClassAPI      = "accountclass"
	AccountClassPOSTTmpl = "{\"Class\":\"%s\"}"
	AccountClassPUTTmpl  = "{\"ID\":%d,\"Class\":\"%s\"}"
)

type accountClass struct {
	ID    int    `json:"ID,omitempty"`
	Class string `json:"Class,omitempty"`
}

type accountClassList struct {
	AccountClasses []accountClass `json:"AccountClasses"`
}

func listAccountClassFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stmtKey := database.StmtKeyAcctClassSelectList
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for listing account classes not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		rows, err := stmt.Query()
		if err != nil {
			c.ApplicationLogf("error retrieving account classes from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		defer rows.Close()
		var as accountClassList
		for rows.Next() {
			var a accountClass
			err := rows.Scan(&a.ID, &a.Class)
			if err != nil {
				c.ApplicationLogf("error processing rows of account classes from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			as.AccountClasses = append(as.AccountClasses, a)
		}
		respondWithJSON(w, http.StatusOK, as)
		return
	})
}

func getAccountClassFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, id, ok := accountClassID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "class ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctClassSelect
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account classes not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		var a accountClass
		err := stmt.QueryRow(id).Scan(&a.ID, &a.Class)
		if err != nil {
			c.ApplicationLogf("error processing account class from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, a)
		return
	})
}

func updateAccountClassFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, i, ok := accountClassID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "class ID not in request")
			return
		}
		a, err := accountClassFromRequest(c, r)
		if err != nil || a.ID != i {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		stmtKey := database.StmtKeyAcctClassUpdate
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for updating an account class not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Class, a.ID)
		if err != nil {
			c.ApplicationLogf("error executing database statement for updating account class: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		if i, e := res.RowsAffected(); i != 1 || e != nil {
			c.ApplicationLogf("error unexpected result from database update of account class: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account class %d updated.", a.ID))
		return
	})
}

func createAccountClassFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := accountClassFromRequest(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}

		// Check it does not already exist
		stmtKey := database.StmtKeyAcctClassByName
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account status by name not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		err = stmt.QueryRow(a.Class).Scan()
		if err != sql.ErrNoRows {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountClassAlreadyExists, fmt.Sprintf("Account class with name %s already exists.", a.Class))
			return
		}

		stmtKey = database.StmtKeyAcctClassInsert
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for creating an account class not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt = (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Class)
		if err != nil {
			c.ApplicationLogf("error executing database statement for creating account class: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil || (i != 1 && i != 0) {
			c.ApplicationLogf("error unexpected result from database for creating account class: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i == 0 {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountClassAlreadyExists, fmt.Sprintf("Account class with name %s already exists.", a.Class))
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account class %s created.", a.Class))
		return
	})
}

func deleteAccountClassFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, id, ok := accountClassID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "Account class ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctClassDelete
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for deleting an account class not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(id)
		if err != nil {
			c.ApplicationLogf("error executing database statement for deleting account class: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil {
			c.ApplicationLogf("error unexpected result from database for deleting account class: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i != 1 {
			respondGeneric(w, http.StatusNotFound, appcodes.AccountClassUnknown, "Account class ID not found.")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account class with ID %d deleted.", id))
		return
	})
}

func getAccountClassRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "AccountClassAllList",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/accountclass",
			HandlerFunc:    listAccountClassFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountClassGet",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/accountclass/{" + MuxVarAccountClassID + ":[0-9]+}",
			HandlerFunc:    getAccountClassFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountClassUpdate",
			Method:         "PUT",
			Pattern:        "/" + APIVersion + "/accountclass/{" + MuxVarAccountClassID + ":[0-9]+}",
			HandlerFunc:    updateAccountClassFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountClassDelete",
			Method:         "DELETE",
			Pattern:        "/" + APIVersion + "/accountclass/{" + MuxVarAccountClassID + ":[0-9]+}",
			HandlerFunc:    deleteAccountClassFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountClassCreate",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/accountclass",
			HandlerFunc:    createAccountClassFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountClassCreateNotAllowed",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/accountclass/{" + MuxVarAccountClassID + ":[0-9]+}",
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func accountClassID(r *http.Request) (string, int, bool) {
	vars := mux.Vars(r)
	id, ok := vars[MuxVarAccountClassID]
	i, err := strconv.Atoi(id)
	if err != nil {
		return id, 0, false
	}
	return id, i, ok
}

func accountClassFromRequest(c *config.Config, r *http.Request) (a accountClass, err error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	err = dec.Decode(&a)
	if err != nil {
		c.ApplicationLogf("error dcoding provided JSON into accountClass: %v", err)
	}
	return
}
