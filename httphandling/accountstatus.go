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
	MuxVarAccountStatusID = "accountStatusID"
	AccountStatusAPIPath  = "/%s/accountstatus%s"
	AccountStatusPOSTTmpl = "{\"Status\":\"%s\"}"
	AccountStatusPUTTmpl  = "{\"ID\":%d,\"Status\":\"%s\"}"
)

type accountStatus struct {
	ID     int    `json:"ID,omitempty"`
	Status string `json:"Status"`
}

type accountStatusList struct {
	AccountStatuses []accountStatus `json:"AccountStatuses"`
}

func listAccountStatusFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stmtKey := database.StmtKeyAcctStatusSelectList
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for listing account statuses not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		rows, err := stmt.Query()
		if err != nil {
			c.ApplicationLogf("error retrieving account statuses from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		defer rows.Close()
		var as accountStatusList
		for rows.Next() {
			var a accountStatus
			err := rows.Scan(&a.ID, &a.Status)
			if err != nil {
				c.ApplicationLogf("error processing rows of account statuses from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			as.AccountStatuses = append(as.AccountStatuses, a)
		}
		respondWithJSON(w, http.StatusOK, as)
		return
	})
}

func getAccountStatusFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, id, ok := accountStatusID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "status ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctStatusSelect
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account statuses not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		var a accountStatus
		err := stmt.QueryRow(id).Scan(&a.ID, &a.Status)
		if err != nil {
			c.ApplicationLogf("error processing account status from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, a)
		return
	})
}

func updateAccountStatusFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, i, ok := accountStatusID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "status ID not in request")
			return
		}
		a, err := accountStatusFromRequest(c, r)
		if err != nil || a.ID != i {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		stmtKey := database.StmtKeyAcctStatusUpdate
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for updating an account status not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Status, a.ID)
		if err != nil {
			c.ApplicationLogf("error executing database statement for updating account status: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		if i, e := res.RowsAffected(); i != 1 || e != nil {
			c.ApplicationLogf("error unexpected result from database update of account status: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account status %d updated.", a.ID))
		return
	})
}

func createAccountStatusFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := accountStatusFromRequest(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}

		// Check it does not already exist
		stmtKey := database.StmtKeyAcctStatusByName
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting an account status by name not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		err = stmt.QueryRow(a.Status).Scan()
		if err != sql.ErrNoRows {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountStatusAlreadyExists, fmt.Sprintf("Account status with name %s already exists.", a.Status))
			return
		}

		stmtKey = database.StmtKeyAcctStatusInsert
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for creating an account status not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt = (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.Status)
		if err != nil {
			c.ApplicationLogf("error executing database statement for creating account status: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil || (i != 1 && i != 0) {
			c.ApplicationLogf("error unexpected result from database for creating account status: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i == 0 {
			respondGeneric(w, http.StatusBadRequest, appcodes.AccountStatusAlreadyExists, fmt.Sprintf("Account status with name %s already exists.", a.Status))
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account status %s created.", a.Status))
		return
	})
}

func deleteAccountStatusFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, id, ok := accountStatusID(r)
		if !ok {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "Account status ID not in request")
			return
		}
		stmtKey := database.StmtKeyAcctStatusDelete
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for deleting an account status not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(id)
		if err != nil {
			c.ApplicationLogf("error executing database statement for deleting account status: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil {
			c.ApplicationLogf("error unexpected result from database for deleting account status: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i != 1 {
			respondGeneric(w, http.StatusNotFound, appcodes.AccountStatusUnknown, "Account status ID not found.")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Account status with ID %d deleted.", id))
		return
	})
}

func getAccountStatusRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "AccountStatusAllList",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/accountstatus",
			HandlerFunc:    listAccountStatusFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountStatusGet",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/accountstatus/{" + MuxVarAccountStatusID + ":[0-9]+}",
			HandlerFunc:    getAccountStatusFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "AccountStatusUpdate",
			Method:         "PUT",
			Pattern:        "/" + APIVersion + "/accountstatus/{" + MuxVarAccountStatusID + ":[0-9]+}",
			HandlerFunc:    updateAccountStatusFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountStatusDelete",
			Method:         "DELETE",
			Pattern:        "/" + APIVersion + "/accountstatus/{" + MuxVarAccountStatusID + ":[0-9]+}",
			HandlerFunc:    deleteAccountStatusFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountStatusCreate",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/accountstatus",
			HandlerFunc:    createAccountStatusFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "AccountStatusCreateNotAllowed",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/accountstatus/{" + MuxVarAccountStatusID + ":[0-9]+}",
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func accountStatusID(r *http.Request) (string, int, bool) {
	vars := mux.Vars(r)
	id, ok := vars[MuxVarAccountStatusID]
	i, err := strconv.Atoi(id)
	if err != nil {
		return id, 0, false
	}
	return id, i, ok
}

func accountStatusFromRequest(c *config.Config, r *http.Request) (a accountStatus, err error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	err = dec.Decode(&a)
	if err != nil {
		c.ApplicationLogf("error dcoding provided JSON into accountStatus: %v", err)
	}
	return
}
