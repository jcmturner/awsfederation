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

func TestAccountClass(t *testing.T) {
	c, _, _, ep, stmtMap, s := test.TestEnv(t)
	defer s.Close()
	fc := make(federationuser.FedUserCache)
	rt := NewRouter(c, stmtMap, &fc)

	var tests = []struct {
		Method         string
		Endpoint       string
		AuthRequired   bool
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		// Create
		{"POST", AccountClassAPI, true, "", fmt.Sprintf(AccountClassPOSTTmpl, test.AccountClassName1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class "+test.AccountClassName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", AccountClassAPI, true, "", fmt.Sprintf(AccountClassPOSTTmpl, test.AccountClassName1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account class with name "+test.AccountClassName1+" already exists.", http.StatusBadRequest, appcodes.AccountClassAlreadyExists)},
		// List 1 entry
		{"GET", AccountClassAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountClasses":[{"ID":%d,"Class":"%s"}]}`, test.AccountClassID1, test.AccountClassName1)},
		// Get
		{"GET", AccountClassAPI, false, "/1", "", http.StatusOK, fmt.Sprintf(`{"ID":%d,"Class":"%s"}`, test.AccountClassID1, test.AccountClassName1)},
		{"POST", AccountClassAPI, true, "", fmt.Sprintf(AccountClassPOSTTmpl, test.AccountClassName2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class "+test.AccountClassName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", AccountClassAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountClasses":[{"ID":%d,"Class":"%s"},{"ID":%d,"Class":"%s"}]}`, test.AccountClassID1, test.AccountClassName1, test.AccountClassID2, test.AccountClassName2)},
		//// Method not allowed
		{"POST", AccountClassAPI, true, "/1", fmt.Sprintf(AccountClassPOSTTmpl, "somethingelse"), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", AccountClassAPI, true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account class with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", AccountClassAPI, true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account class ID not found.", http.StatusNotFound, appcodes.AccountClassUnknown)},
		{"PUT", AccountClassAPI, true, "/1", fmt.Sprintf(AccountClassPUTTmpl, 1, "somethingelse"), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account class %d updated.", test.AccountClassID1), http.StatusOK, appcodes.Info)},
	}
	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyAcctClassByName].ExpectQuery().WithArgs(test.AccountClassName1).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	ep[database.StmtKeyAcctClassInsert].ExpectExec().WithArgs(test.AccountClassName1).WillReturnResult(sqlmock.NewResult(0, 1))

	rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
	ep[database.StmtKeyAcctClassByName].ExpectQuery().WithArgs(test.AccountClassName1).WillReturnRows(rows)

	rows = sqlmock.NewRows([]string{"id", "class"}).
		AddRow(1, test.AccountClassName1)
	ep[database.StmtKeyAcctClassSelectList].ExpectQuery().WillReturnRows(rows)

	rows = sqlmock.NewRows([]string{"id", "class"}).
		AddRow(1, test.AccountClassName1)
	ep[database.StmtKeyAcctClassSelect].ExpectQuery().WithArgs(test.AccountClassID1).WillReturnRows(rows)

	ep[database.StmtKeyAcctClassByName].ExpectQuery().WithArgs(test.AccountClassName2).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	ep[database.StmtKeyAcctClassInsert].ExpectExec().WithArgs(test.AccountClassName2).WillReturnResult(sqlmock.NewResult(1, 1))
	rows2 := sqlmock.NewRows([]string{"id", "class"}).
		AddRow(1, test.AccountClassName1).
		AddRow(2, test.AccountClassName2)
	ep[database.StmtKeyAcctClassSelectList].ExpectQuery().WillReturnRows(rows2)
	ep[database.StmtKeyAcctClassDelete].ExpectExec().WithArgs(test.AccountClassID2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctClassDelete].ExpectExec().WithArgs(test.AccountClassID2).WillReturnResult(sqlmock.NewResult(0, 0))
	ep[database.StmtKeyAcctClassUpdate].ExpectExec().WithArgs("somethingelse", test.AccountClassID1).WillReturnResult(sqlmock.NewResult(0, 1))

	for _, test := range tests {
		url := fmt.Sprintf("http://127.0.0.1:8443/%s/%s%s", APIVersion, test.Endpoint, test.Path)
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
