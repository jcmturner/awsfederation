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

func TestAccountType(t *testing.T) {
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
		{"POST", AccountTypeAPI, true, "", fmt.Sprintf(AccountTypePOSTTmpl, test.AccountTypeName1, test.AccountClassID1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type "+test.AccountTypeName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", AccountTypeAPI, true, "", fmt.Sprintf(AccountTypePOSTTmpl, test.AccountTypeName1, test.AccountClassID1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account Type with name "+test.AccountTypeName1+" already exists.", http.StatusBadRequest, appcodes.AccountTypeAlreadyExists)},
		// List 1 entry
		{"GET", AccountTypeAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountTypes":[`+AccountTypeGETTmpl+`]}`, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1)},
		// Get
		{"GET", AccountTypeAPI, false, "/1", "", http.StatusOK, fmt.Sprintf(AccountTypeGETTmpl, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1)},
		{"POST", AccountTypeAPI, true, "", fmt.Sprintf(AccountTypePOSTTmpl, test.AccountTypeName2, test.AccountClassID2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type "+test.AccountTypeName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", AccountTypeAPI, false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountTypes":[`+AccountTypeGETTmpl+","+AccountTypeGETTmpl+`]}`, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountTypeID2, test.AccountTypeName2, test.AccountClassID2)},
		//// Method not allowed
		{"POST", AccountTypeAPI, true, "/1", fmt.Sprintf(AccountTypePOSTTmpl, "somethingelse", test.AccountClassID1), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", AccountTypeAPI, true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", AccountTypeAPI, true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account Type ID not found.", http.StatusNotFound, appcodes.AccountTypeUnknown)},
		{"PUT", AccountTypeAPI, true, "/1", fmt.Sprintf(AccountTypePUTTmpl, 1, "somethingelse", test.AccountClassID2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account Type %d updated.", test.AccountTypeID1), http.StatusOK, appcodes.Info)},
	}
	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyAcctTypeByName].ExpectQuery().WithArgs(test.AccountTypeName1).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	ep[database.StmtKeyAcctTypeInsert].ExpectExec().WithArgs(test.AccountTypeName1, test.AccountClassID1).WillReturnResult(sqlmock.NewResult(0, 1))

	rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
	ep[database.StmtKeyAcctTypeByName].ExpectQuery().WithArgs(test.AccountTypeName1).WillReturnRows(rows)

	rows = sqlmock.NewRows([]string{"id", "type", "class_id"}).
		AddRow(1, test.AccountTypeName1, test.AccountClassID1)
	ep[database.StmtKeyAcctTypeSelectList].ExpectQuery().WillReturnRows(rows)

	rows = sqlmock.NewRows([]string{"id", "type", "class_id"}).
		AddRow(1, test.AccountTypeName1, test.AccountClassID1)
	ep[database.StmtKeyAcctTypeSelect].ExpectQuery().WithArgs(test.AccountTypeID1).WillReturnRows(rows)

	ep[database.StmtKeyAcctTypeByName].ExpectQuery().WithArgs(test.AccountTypeName2).WillReturnRows(sqlmock.NewRows([]string{"id"}))
	ep[database.StmtKeyAcctTypeInsert].ExpectExec().WithArgs(test.AccountTypeName2, test.AccountClassID2).WillReturnResult(sqlmock.NewResult(1, 1))

	rows = sqlmock.NewRows([]string{"id", "type", "class_id"}).
		AddRow(1, test.AccountTypeName1, test.AccountClassID1).
		AddRow(2, test.AccountTypeName2, test.AccountClassID2)
	ep[database.StmtKeyAcctTypeSelectList].ExpectQuery().WillReturnRows(rows)
	ep[database.StmtKeyAcctTypeDelete].ExpectExec().WithArgs(test.AccountTypeID2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctTypeDelete].ExpectExec().WithArgs(test.AccountTypeID2).WillReturnResult(sqlmock.NewResult(0, 0))
	ep[database.StmtKeyAcctTypeUpdate].ExpectExec().WithArgs("somethingelse", test.AccountTypeID1, test.AccountClassID2).WillReturnResult(sqlmock.NewResult(0, 1))

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
