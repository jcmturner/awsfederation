package httphandling

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"io"
	"net/http"
	"strings"
)

const (
	MuxVarRoleARN       = "roleARN"
	MuxVarRoleAccountID = "accountID"
	IAMRoleARNFormat    = "arn:aws:iam::%s:role/%s"
	QueryRoleAccountIDs = "accountids"
)

type role struct {
	ARN       string `json:"ARN"`
	AccountID string `json:"AccountID,omitempty"`
}

type roleList struct {
	Roles []role `json:"Roles"`
}

func listRoleFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stmtKey := database.StmtKeyRoleSelectList
		acctList := r.URL.Query().Get(QueryRoleAccountIDs)
		var accts []string
		if acctList != "" {
			accts = strings.Split(acctList, ",")
			stmtKey = database.StmtKeyRoleByAcct
		}
		if stmt, ok := (*stmtMap)[stmtKey]; ok {
			var rows *sql.Rows
			var err error
			if stmtKey == database.StmtKeyRoleByAcct {
				rows, err = stmt.Query(strings.Join(accts, ", "))
			} else {
				rows, err = stmt.Query()
			}
			if err != nil {
				c.ApplicationLogf("error retrieving roles from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			defer rows.Close()
			var as roleList
			for rows.Next() {
				var a role
				err := rows.Scan(&a.ARN, &a.AccountID)
				if err != nil {
					c.ApplicationLogf("error processing rows of roles from database: %v", err)
					respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
					return
				}
				as.Roles = append(as.Roles, a)
			}
			respondWithJSON(w, http.StatusOK, as)
			return
		}
		c.ApplicationLogf("error, prepared statement for listing roles not found")
		respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
		return
	})
}

func getRoleFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl, err := roleFromURL(r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, err.Error())
			return
		}
		if stmt, ok := (*stmtMap)[database.StmtKeyRoleSelect]; ok {
			var a role
			err := stmt.QueryRow(rl.ARN).Scan(&a.ARN, &a.AccountID)
			if err != nil {
				c.ApplicationLogf("error processing role from database: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			respondWithJSON(w, http.StatusOK, a)
			return
		}
		c.ApplicationLogf("error, prepared statement for getting an roles not found")
		respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
		return
	})
}

func createRoleFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl, err := roleFromPOST(c, r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, "invalid post data")
			return
		}
		if stmt, ok := (*stmtMap)[database.StmtKeyRoleInsert]; ok {
			res, err := stmt.Exec(rl.ARN, rl.AccountID)
			if err != nil {
				c.ApplicationLogf("error executing database statement for creating role: %v", err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			i, e := res.RowsAffected()
			if e != nil || (i != 1 && i != 0) {
				c.ApplicationLogf("error unexpected result from database for creating role: expected (1) row affected, got (%d); error: %v", i, e)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
				return
			}
			if i == 0 {
				respondGeneric(w, http.StatusBadRequest, appcodes.RoleAlreadyExists, fmt.Sprintf("Role with ARN %s already exists.", rl.ARN))
				return
			}
			respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Role with ARN %s created.", rl.ARN))
			return
		}
		c.ApplicationLogf("error, prepared statement for creating an role not found")
		respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
		return
	})
}

func deleteRoleFunc(c *config.Config, stmtMap *database.StmtMap) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl, err := roleFromURL(r)
		if err != nil {
			respondGeneric(w, http.StatusBadRequest, appcodes.BadData, err.Error())
			return
		}
		if stmt, ok := (*stmtMap)[database.StmtKeyRoleDelete]; ok {
			res, err := stmt.Exec(rl.ARN)
			if err != nil {
				c.ApplicationLogf("error executing database statement for deleting Role %s: %v", rl.ARN, err)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, err.Error())
				return
			}
			i, e := res.RowsAffected()
			if e != nil {
				c.ApplicationLogf("error unexpected result from database for deleting role: expected (1) row affected, got (%d); error: %v", i, e)
				respondGeneric(w, http.StatusInternalServerError, appcodes.DatabaseError, "unexpected response from databse")
				return
			}
			if i != 1 {
				respondGeneric(w, http.StatusNotFound, appcodes.RoleUnknown, fmt.Sprintf("Role with ARN %s not found.", rl.ARN))
				return
			}
			respondGeneric(w, http.StatusOK, appcodes.Info, fmt.Sprintf("Role with ARN %s deleted.", rl.ARN))
			return
		}
		c.ApplicationLogf("error, prepared statement for deleting a Role not found")
		respondGeneric(w, http.StatusInternalServerError, appcodes.ServerConfigurationError, "database statement not found")
		return
	})
}

func getRoleRoutes(c *config.Config, stmtMap *database.StmtMap) []Route {
	return []Route{
		{
			Name:           "RoleAllList",
			Method:         "GET",
			Pattern:        "/" + APIVersion + "/role",
			HandlerFunc:    listRoleFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "RoleGet",
			Method:         "GET",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/role/"+IAMRoleARNFormat, "{"+MuxVarRoleAccountID+":[0-9]{12}}", "{"+MuxVarRoleARN+"}"),
			HandlerFunc:    getRoleFunc(c, stmtMap),
			Authentication: false,
		},
		{
			Name:           "RoleUpdateNotAllowed",
			Method:         "PUT",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/role/"+IAMRoleARNFormat, "{"+MuxVarRoleAccountID+":[0-9]{12}}", "{"+MuxVarRoleARN+"}"),
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
		{
			Name:           "RoleDelete",
			Method:         "DELETE",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/role/"+IAMRoleARNFormat, "{"+MuxVarRoleAccountID+":[0-9]{12}}", "{"+MuxVarRoleARN+"}"),
			HandlerFunc:    deleteRoleFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "RoleCreate",
			Method:         "POST",
			Pattern:        "/" + APIVersion + "/role",
			HandlerFunc:    createRoleFunc(c, stmtMap),
			Authentication: true,
		},
		{
			Name:           "RoleCreateNotAllowed",
			Method:         "POST",
			Pattern:        fmt.Sprintf("/"+APIVersion+"/role/"+IAMRoleARNFormat, "{"+MuxVarRoleAccountID+":[0-9]{12}}", "{"+MuxVarRoleARN+"}"),
			HandlerFunc:    MethodNotAllowed(),
			Authentication: true,
		},
	}
}

func roleFromURL(r *http.Request) (a role, err error) {
	vars := mux.Vars(r)
	var rolename string = vars[MuxVarRoleARN]
	var accountID string = vars[MuxVarRoleAccountID]
	if accountID == "" || rolename == "" {
		err = errors.New("role ARN not in request")
		return
	}
	a.ARN = fmt.Sprintf(IAMRoleARNFormat, accountID, rolename)
	a.AccountID = accountID
	return
}

func roleFromPOST(c *config.Config, r *http.Request) (rl role, err error) {
	reader := io.LimitReader(r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(reader)
	err = dec.Decode(&rl)
	if err != nil {
		c.ApplicationLogf("error decoding provided JSON into role: %v", err)
	}
	a, e := arn.Parse(rl.ARN)
	if e != nil {
		err = fmt.Errorf("invalid Role ARN: %s", e)
		c.ApplicationLogf("invalid ARN [%s] in Role provided: %v", rl.ARN, err)
	}
	rl.AccountID = a.AccountID
	return
}
