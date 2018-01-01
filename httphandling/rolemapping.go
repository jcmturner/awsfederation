package httphandling

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"io"
	"net/http"
	"strings"
)

const (
	FilterAuthz      = "authz"
	FilterARN        = "arn"
	FilterAccountIDs = "account"
)

type roleMapping struct {
	ID                string `json:"ID,omitempty"`
	RoleARN           string `json:"RoleARN"`
	AuthzAttribute    string `json:"AuthzAttribute"`
	AccountID         string `json:"AccountID,omitempty"`
	Policy            string `json:"Policy,omitempty"`
	Duration          int    `json:"Duration,omitempty"`
	SessionNameFormat string `json:"SessionNameFormat,omitempty"`
}

type roleMappingList struct {
	RoleMappings []roleMapping `json:"RoleMappings"`
}

func listRoleMappingFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stmtKey := database.StmtKeyRoleMappingSelectList
		var filter []string
		for fkey, fval := range r.URL.Query() {
			switch fkey {
			case FilterAccountIDs:
				stmtKey = database.StmtKeyRoleMappingByAcct
				filter = fval
				break
			case FilterARN:
				stmtKey = database.StmtKeyRoleMappingByARN
				filter = fval
				break
			case FilterAuthz:
				stmtKey = database.StmtKeyRoleMappingByAuthz
				filter = fval
				break
			}
		}

		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for listing Role Mappings not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}

		stmt := (*stmtMap)[stmtKey]
		var rows *sql.Rows
		var err error
		if stmtKey != database.StmtKeyRoleMappingSelectList {
			rows, err = stmt.Query()
		} else {
			rows, err = stmt.Query(strings.Join(filter, ", "))
		}
		if err != nil {
			c.ApplicationLogf("error retrieving Role Mappings from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		defer rows.Close()
		var as roleMappingList
		for rows.Next() {
			var a roleMapping
			err := rows.Scan(&a.ID, &a.AccountID, &a.RoleARN, &a.AuthzAttribute, &a.Policy, &a.Duration, &a.SessionNameFormat)
			if err != nil {
				c.ApplicationLogf("error processing rows of Role Mappings from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			as.RoleMappings = append(as.RoleMappings, a)
		}
		respondWithJSON(w, http.StatusOK, as)
		return
	})
}

func getRoleMappingFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestToRoleUUID(r)
		if id == "" {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "Role Mapping UUID not found in request")
			return
		}
		stmtKey := database.StmtKeyRoleMappingSelect
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for getting Role Mapping not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		var a roleMapping
		err := stmt.QueryRow(id).Scan(&a.ID, &a.AccountID, &a.RoleARN, &a.AuthzAttribute, &a.Policy, &a.Duration, &a.SessionNameFormat)
		if err != nil {
			c.ApplicationLogf("error processing Role Mapping from database: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		respondWithJSON(w, http.StatusOK, a)
		return
	})
}

func updateRoleMappingFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestToRoleUUID(r)
		if id == "" {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "class ID not in request")
			return
		}
		a, err := roleMappingFromPost(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		stmtKey := database.StmtKeyRoleMappingUpdate
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for updating Role Mapping not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.AccountID, a.RoleARN, a.AuthzAttribute, a.Policy, a.Duration, a.SessionNameFormat, id)
		if err != nil {
			c.ApplicationLogf("error executing database statement for updating Role Mapping: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		if i, e := res.RowsAffected(); i != 1 || e != nil {
			c.ApplicationLogf("error unexpected result from database update of Role Mapping: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Role Mapping %s updated.", a.ID))
		return
	})
}

func createRoleMappingFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := roleMappingFromPost(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		a.ID, err = uuid.GenerateUUID()
		if err != nil {
			e := fmt.Errorf("error generating UUID for new Role Mapping: %v", err)
			c.ApplicationLogf(e.Error())
			respondGeneric(w, http.StatusInternalServerError, appcodes.UUIDGenerationError, e.Error())
			return
		}
		stmtKey := database.StmtKeyRoleMappingInsert
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for creating Role Mapping not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(a.ID, a.AccountID, a.RoleARN, a.AuthzAttribute, a.Policy, a.Duration, a.SessionNameFormat)
		if err != nil {
			c.ApplicationLogf("error executing database statement for creating Role Mapping: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil || (i != 1 && i != 0) {
			c.ApplicationLogf("error unexpected result from database for creating Role Mapping: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i == 0 {
			respondGeneric(w, http.StatusBadRequest, appcodes.RoleMappingAlreadyExists, fmt.Sprintf("Role Mapping with ARN %s and Authz Attrbute %s already exists.", a.RoleARN, a.AuthzAttribute))
			return
		}
		respondCreated(w, a.ID, fmt.Sprintf("Role Mapping %s created.", a.ID))
		return
	})
}

func deleteRoleMappingFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestToRoleUUID(r)
		if id == "" {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "Role Mapping ID not in request")
			return
		}
		stmtKey := database.StmtKeyRoleMappingDelete
		if _, ok := (*stmtMap)[stmtKey]; !ok {
			c.ApplicationLogf("error, prepared statement for deleting Role Mapping not found")
			respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
			return
		}
		stmt := (*stmtMap)[stmtKey]
		res, err := stmt.Exec(id)
		if err != nil {
			c.ApplicationLogf("error executing database statement for deleting Role Mapping: %v", err)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
			return
		}
		i, e := res.RowsAffected()
		if e != nil {
			c.ApplicationLogf("error unexpected result from database for deleting Role Mapping: expected (1) row affected, got (%d); error: %v", i, e)
			respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
			return
		}
		if i != 1 {
			respondGeneric(w, http.StatusNotFound, appcodes.RoleMappingUnknown, "Role Mapping ID not found.")
			return
		}
		respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Role Mapping with ID %s deleted.", id))
		return
	})
}

func getRoleMappingRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "RoleMappingAllList",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/rolemapping",
			HandlerFunc:    listRoleMappingFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "RoleMappingGet",
			Method:         "GET",
			Pattern:        fmt.Sprintf(`/%s/rolemapping/{%s:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}`, APIVersion, MuxVarRoleUUID),
			HandlerFunc:    getRoleMappingFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "RoleMappingUpdate",
			Method:         "PUT",
			Pattern:        fmt.Sprintf(`/%s/rolemapping/{%s:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}`, APIVersion, MuxVarRoleUUID),
			HandlerFunc:    updateRoleMappingFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "RoleMappingDelete",
			Method:         "DELETE",
			Pattern:        fmt.Sprintf(`/%s/rolemapping/{%s:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}`, APIVersion, MuxVarRoleUUID),
			HandlerFunc:    deleteRoleMappingFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "RoleMappingCreate",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/rolemapping",
			HandlerFunc:    createRoleMappingFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "RoleMappingCreateNotAllowed",
			Method:         "POST",
			Pattern:        fmt.Sprintf(`/%s/rolemapping/{%s:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}`, APIVersion, MuxVarRoleUUID),
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func roleMappingFromPost(c *config.Config, r *http.Request) (rm roleMapping, err error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	err = dec.Decode(&rm)
	if err != nil {
		c.ApplicationLogf("error decoding provided JSON into roleMapping: %v", err)
	}
	a, e := arn.Parse(rm.RoleARN)
	if e != nil {
		err = fmt.Errorf("invalid Role ARN: %s", e)
		c.ApplicationLogf("invalid ARN [%s] in roleMapping provided: %v", rm.RoleARN, err)
	}
	rm.AccountID = a.AccountID
	return
}
