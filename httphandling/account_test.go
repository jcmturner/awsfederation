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
	AccountAPIPath  = "/%s/account%s"
	AccountGETTmpl  = "{\"ID\":\"%s\",\"Email\":\"%s\",\"Name\":\"%s\",\"Type\":{\"ID\":%d,\"Type\":\"%s\",\"Class\":{\"ID\":%d,\"Class\":\"%s\"}},\"Status\":{\"ID\":%d,\"Status\":\"%s\"},\"FederationUserARN\":\"%s\"}"
	AccountPOSTTmpl = "{\"ID\":\"%s\",\"Email\":\"%s\",\"Name\":\"%s\",\"Type\":{\"ID\":%d},\"Status\":{\"ID\":%d},\"FederationUserARN\":\"%s\"}"
)

func TestAccount(t *testing.T) {
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
		{"POST", true, "", fmt.Sprintf(AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account "+test.AWSAccountID1+" created.", http.StatusOK, appcodes.Info)},
		// Handle create duplicate
		{"POST", true, "", fmt.Sprintf(AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1), http.StatusBadRequest, fmt.Sprintf(test.GenericResponseTmpl, "Account with ID "+test.AWSAccountID1+" already exists.", http.StatusBadRequest, appcodes.AccountAlreadyExists)},
		// List 1 entry
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"Accounts":[`+AccountGETTmpl+`]}`, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1)},
		// Get
		{"GET", false, "/" + test.AWSAccountID1, "", http.StatusOK, fmt.Sprintf(AccountGETTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1)},
		{"POST", true, "", fmt.Sprintf(AccountPOSTTmpl, test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountStatusID2, test.FedUserArn2), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account "+test.AWSAccountID2+" created.", http.StatusOK, appcodes.Info)},
		//// List multiple
		{"GET", false, "", "", http.StatusOK, fmt.Sprintf(`{"Accounts":[`+AccountGETTmpl+","+AccountGETTmpl+`]}`, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1, test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountTypeName2, test.AccountClassID2, test.AccountClassName2, test.AccountStatusID2, test.AccountStatusName2, test.FedUserArn2)},
		//// Method not allowed
		{"POST", true, "/" + test.AWSAccountID1, fmt.Sprintf(AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"DELETE", true, "/" + test.AWSAccountID2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Account with ID "+test.AWSAccountID2+" deleted.", http.StatusOK, appcodes.Info)},
		{"DELETE", true, "/" + test.AWSAccountID2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Account ID not found.", http.StatusNotFound, appcodes.AccountUnknown)},
		{"PUT", true, "/" + test.AWSAccountID1, fmt.Sprintf(AccountPOSTTmpl, test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID2, test.AccountStatusID1, test.FedUserArn1), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, fmt.Sprintf("Account %s updated.", test.AWSAccountID1), http.StatusOK, appcodes.Info)},
	}
	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyAcctInsert].ExpectExec().WithArgs(test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctInsert].ExpectExec().WithArgs(test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountStatusID1, test.FedUserArn1).WillReturnResult(sqlmock.NewResult(1, 0))
	rows1 := sqlmock.NewRows([]string{"id", "email", "name", "typeid", "type", "classid", "class", "statusid", "status", "feduser"}).
		AddRow(test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1)
	ep[database.StmtKeyAcctSelectList].ExpectQuery().WillReturnRows(rows1)
	rows1a := sqlmock.NewRows([]string{"id", "email", "name", "typeid", "type", "classid", "class", "statusid", "status", "feduser"}).
		AddRow(test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1)
	ep[database.StmtKeyAcctSelect].ExpectQuery().WithArgs(test.AWSAccountID1).WillReturnRows(rows1a)
	ep[database.StmtKeyAcctInsert].ExpectExec().WithArgs(test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountStatusID2, test.FedUserArn2).WillReturnResult(sqlmock.NewResult(1, 1))
	rows2 := sqlmock.NewRows([]string{"id", "email", "name", "typeid", "type", "classid", "class", "statusid", "status", "feduser"}).
		AddRow(test.AWSAccountID1, test.AccountEmail1, test.AccountName1, test.AccountTypeID1, test.AccountTypeName1, test.AccountClassID1, test.AccountClassName1, test.AccountStatusID1, test.AccountStatusName1, test.FedUserArn1).
		AddRow(test.AWSAccountID2, test.AccountEmail2, test.AccountName2, test.AccountTypeID2, test.AccountTypeName2, test.AccountClassID2, test.AccountClassName2, test.AccountStatusID2, test.AccountStatusName2, test.FedUserArn2)
	ep[database.StmtKeyAcctSelectList].ExpectQuery().WillReturnRows(rows2)
	ep[database.StmtKeyAcctDelete].ExpectExec().WithArgs(test.AWSAccountID2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyAcctDelete].ExpectExec().WithArgs(test.AWSAccountID2).WillReturnResult(sqlmock.NewResult(0, 0))
	ep[database.StmtKeyAcctUpdate].ExpectExec().WithArgs(test.AccountEmail1, test.AccountName1, test.AccountTypeID2, test.AccountStatusID1, test.FedUserArn1, test.AWSAccountID1).WillReturnResult(sqlmock.NewResult(0, 1))

	for _, test := range tests {
		url := fmt.Sprintf(AccountAPIPath, APIVersion, test.Path)
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
