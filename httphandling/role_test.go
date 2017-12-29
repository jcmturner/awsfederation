package httphandling

import (
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/awsfederation/appcodes"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsfederation/test"
	"github.com/stretchr/testify/assert"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	RoleAPIPath  = "/%s/role%s"
	RolePOSTTmpl = "{\"ARN\":\"%s\"}"
)

func TestRole(t *testing.T) {
	c, _, _, ep, stmtMap, s := test.TestEnv(t)
	defer s.Close()
	fc := make(federationuser.FedUserCache)
	rt := NewRouter(c, stmtMap, &fc)

	var tests = []struct {
		Method         string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Create
		{"POST", true, "", fmt.Sprintf(RolePOSTTmpl, test.RoleARN1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Role with ARN "+test.RoleARN1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", true, "", fmt.Sprintf(RolePOSTTmpl, test.RoleARN1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Role with ARN "+test.RoleARN1+" already exists.", http.StatusBadRequest, appcodes.RoleAlreadyExists)},
		// List 1 entry
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"Roles":[{"ARN":"%s","AccountID":"%s"}]}`, test.RoleARN1, test.AWSAccountID1)},
		// Get
		{"GET", false, "/" + test.RoleARN1, "", http.StatusOK, fmt.Sprintf(`{"ARN":"%s","AccountID":"%s"}`, test.RoleARN1, test.AWSAccountID1)},
		{"POST", true, "", fmt.Sprintf(RolePOSTTmpl, test.RoleARN2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Role with ARN "+test.RoleARN2+" created.", http.StatusOK, appcodes.Info)},
		// List multiple
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"Roles":[{"ARN":"%s","AccountID":"%s"},{"ARN":"%s","AccountID":"%s"}]}`, test.RoleARN1, test.AWSAccountID1, test.RoleARN2, test.AWSAccountID2)},
		// Method not allowed
		{"POST", true, "/" + test.RoleARN1, fmt.Sprintf(RolePOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", true, "/" + test.RoleARN2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Role with ARN "+test.RoleARN2+" deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", true, "/" + test.RoleARN2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Role with ARN "+test.RoleARN2+" not found.", http.StatusNotFound, appcodes.RoleUnknown)},
		{"PUT", true, "/" + test.RoleARN1, fmt.Sprintf(RolePOSTTmpl, test.RoleARN1), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The PUT method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
	}
	// Set the expected database calls that are performed as part of the table tests
	// Create
	ep[database.StmtKeyRoleInsert].ExpectExec().WithArgs(test.RoleARN1, test.AWSAccountID1).WillReturnResult(sqlmock.NewResult(0, 1))
	// Handle create duplicate
	ep[database.StmtKeyRoleInsert].ExpectExec().WithArgs(test.RoleARN1, test.AWSAccountID1).WillReturnResult(sqlmock.NewResult(1, 0))
	// List 1 entry
	rows1 := sqlmock.NewRows([]string{"arn", "account_id"}).
		AddRow(test.RoleARN1, test.AWSAccountID1)
	ep[database.StmtKeyRoleSelectList].ExpectQuery().WillReturnRows(rows1)
	// Get
	rows1a := sqlmock.NewRows([]string{"arn", "account_id"}).
		AddRow(test.RoleARN1, test.AWSAccountID1)
	ep[database.StmtKeyRoleSelect].ExpectQuery().WithArgs(test.RoleARN1).WillReturnRows(rows1a)
	// POST
	ep[database.StmtKeyRoleInsert].ExpectExec().WithArgs(test.RoleARN2, test.AWSAccountID2).WillReturnResult(sqlmock.NewResult(1, 1))
	// GET list
	rows2 := sqlmock.NewRows([]string{"arn", "account_id"}).
		AddRow(test.RoleARN1, test.AWSAccountID1).
		AddRow(test.RoleARN2, test.AWSAccountID2)
	ep[database.StmtKeyRoleSelectList].ExpectQuery().WillReturnRows(rows2)
	// DELETE
	ep[database.StmtKeyRoleDelete].ExpectExec().WithArgs(test.RoleARN2).WillReturnResult(sqlmock.NewResult(0, 1))
	// DELETE
	ep[database.StmtKeyRoleDelete].ExpectExec().WithArgs(test.RoleARN2).WillReturnResult(sqlmock.NewResult(0, 0))

	for _, test := range tests {
		url := fmt.Sprintf(RoleAPIPath, APIVersion, test.Path)
		request, err := http.NewRequest(test.Method, url, strings.NewReader(test.PostPayload))
		if err != nil {
			t.Fatalf("error building request: %v", err)
		}
		response := httptest.NewRecorder()
		rt.ServeHTTP(response, request)
		if test.AuthRequired {
			// Check it was unauthorized before passing auth creds
			assert.Equal(t, http.StatusUnauthorized, response.Code, "Expected unauthorized error")
			// Now authenticated (using testing static auth)
			response = httptest.NewRecorder()
			request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser@TESTING:"+config.MockStaticSecret)))
			rt.ServeHTTP(response, request)
		}
		assert.Equal(t, test.HttpCode, response.Code, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.Code, test.Method, url))
		assert.Equal(t, test.ResponseString, response.Body.String(), fmt.Sprintf("Response not as expected (%s %s)", test.Method, url))
	}
}
