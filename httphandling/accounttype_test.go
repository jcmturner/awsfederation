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
	AccountTypeAPIPath  = "/%s/accounttype%s"
	AccountTypeGETTmpl  = "{\"ID\":%d,\"Type\":\"%s\",\"Class\":{\"ID\":%d}}"
	AccountTypePOSTTmpl = "{\"Type\":\"%s\",\"Class\":{\"ID\":%d}}"
	AccountTypePUTTmpl  = "{\"ID\":%d,\"Type\":\"%s\",\"Class\":{\"ID\":%d}}"
)

func TestAccountType(t *testing.T) {
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
		{"POST", true, "", fmt.Sprintf(AccountTypePOSTTmpl, test.AccountTypeName1, test.AccountClassID1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type "+test.AccountTypeName1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", true, "", fmt.Sprintf(AccountTypePOSTTmpl, test.AccountTypeName1, test.AccountClassID1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account Type with name "+test.AccountTypeName1+" already exists.", http.StatusBadRequest, appcodes.AccountTypeAlreadyExists)},
		// List 1 entry
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountTypes":[`+AccountTypeGETTmpl+`]}`, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1)},
		// Get
		{"GET", false, "/1", "", http.StatusOK, fmt.Sprintf(AccountTypeGETTmpl, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1)},
		{"POST", true, "", fmt.Sprintf(AccountTypePOSTTmpl, test.AccountTypeName2, test.AccountClassID2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type "+test.AccountTypeName2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"AccountTypes":[`+AccountTypeGETTmpl+","+AccountTypeGETTmpl+`]}`, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountTypeID2, test.AccountTypeName2, test.AccountClassID2)},
		//// Method not allowed
		{"POST", true, "/1", fmt.Sprintf(AccountTypePOSTTmpl, "somethingelse", test.AccountClassID1), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", true, "/2", "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account Type with ID 2 deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", true, "/2", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account Type ID not found.", http.StatusNotFound, appcodes.AccountTypeUnknown)},
		{"PUT", true, "/1", fmt.Sprintf(AccountTypePUTTmpl, 1, "somethingelse", test.AccountClassID2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account Type %d updated.", test.AccountTypeID1), http.StatusOK, appcodes.Info)},
	}
	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyAcctTypeInsert].ExpectExec().WithArgs(test.AccountTypeName1).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctTypeInsert].ExpectExec().WithArgs(test.AccountTypeName1).WillReturnResult(sqlmock.NewResult(1, 0))
	rows1 := sqlmock.NewRows([]string{"id", "type", "class_id"}).
		AddRow(1, test.AccountTypeName1, test.AccountClassID1)
	ep[database.StmtKeyAcctTypeSelectList].ExpectQuery().WillReturnRows(rows1)
	rows1a := sqlmock.NewRows([]string{"id", "type", "class_id"}).
		AddRow(1, test.AccountTypeName1, test.AccountClassID1)
	ep[database.StmtKeyAcctTypeSelect].ExpectQuery().WithArgs(test.AccountTypeID1).WillReturnRows(rows1a)
	ep[database.StmtKeyAcctTypeInsert].ExpectExec().WithArgs(test.AccountTypeName2).WillReturnResult(sqlmock.NewResult(1, 1))
	rows2 := sqlmock.NewRows([]string{"id", "type", "class_id"}).
		AddRow(1, test.AccountTypeName1, test.AccountClassID1).
		AddRow(2, test.AccountTypeName2, test.AccountClassID2)
	ep[database.StmtKeyAcctTypeSelectList].ExpectQuery().WillReturnRows(rows2)
	ep[database.StmtKeyAcctTypeDelete].ExpectExec().WithArgs(test.AccountTypeID2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctTypeDelete].ExpectExec().WithArgs(test.AccountTypeID2).WillReturnResult(sqlmock.NewResult(0, 0))
	ep[database.StmtKeyAcctTypeUpdate].ExpectExec().WithArgs("somethingelse", test.AccountTypeID1, test.AccountClassID2).WillReturnResult(sqlmock.NewResult(0, 1))

	for _, test := range tests {
		url := fmt.Sprintf(AccountTypeAPIPath, APIVersion, test.Path)
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
