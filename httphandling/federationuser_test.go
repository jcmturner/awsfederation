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
	"time"
)

func TestFederationUser(t *testing.T) {
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
		{"POST", FederationUserAPI, true, "", fmt.Sprintf(FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn1+" created.", http.StatusOK, appcodes.Info)},
		{"GET", FederationUserAPI, false, "/" + test.FedUserArn1, "", http.StatusOK, fmt.Sprintf(FederationUserResponseTmpl, test.FedUserArn1, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial)},
		{"GET", FederationUserAPI, false, "", "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\"]}"},
		{"GET", FederationUserAPI, false, fmt.Sprintf("/arn:aws:iam::%s:user", test.AWSAccountID1), "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\"]}"},
		{"GET", FederationUserAPI, false, "/arn:aws:iam::123456789012:user/notexist", "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
		{"POST", FederationUserAPI, true, "", fmt.Sprintf(FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusConflict, fmt.Sprintf(test.GenericResponseTmpl, "Federation user already exists.", http.StatusConflict, appcodes.FederationUserAlreadyExists)},
		{"POST", FederationUserAPI, true, "/" + test.FedUserArn1, fmt.Sprintf(FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusMethodNotAllowed, fmt.Sprintf(test.GenericResponseTmpl, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcodes.BadData)},
		{"POST", FederationUserAPI, true, "", fmt.Sprintf(FederationUserPOSTTmpl, test.FedUserName2, test.FedUserArn2, test.IAMUser2SecretAccessKey, test.IAMUser2SessionToken, test.IAMUser2Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL2, test.IAMUser2MFASerial, test.IAMUser2MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn2+" created.", http.StatusOK, appcodes.Info)},
		{"DELETE", FederationUserAPI, true, "/" + test.FedUserArn2, "", http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn2+" deleted.", http.StatusOK, appcodes.Info)},
		{"GET", FederationUserAPI, false, "/" + test.FedUserArn2, "", http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
		{"POST", FederationUserAPI, true, "", fmt.Sprintf(FederationUserPOSTTmpl, test.FedUserName2, test.FedUserArn2, test.IAMUser2SecretAccessKey, test.IAMUser2SessionToken, test.IAMUser2Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL2, test.IAMUser2MFASerial, test.IAMUser2MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn2+" created.", http.StatusOK, appcodes.Info)},
		{"GET", FederationUserAPI, false, "", "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\",\"" + test.FedUserArn2 + "\"]}"},
		{"GET", FederationUserAPI, false, fmt.Sprintf("/arn:aws:iam::%s:user", test.AWSAccountID1), "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn1 + "\"]}"},
		{"GET", FederationUserAPI, false, fmt.Sprintf("/arn:aws:iam::%s:user", test.AWSAccountID2), "", http.StatusOK, "{\"FederationUsers\":[\"" + test.FedUserArn2 + "\"]}"},
		{"PUT", FederationUserAPI, true, "/arn:aws:iam::123456789012:user/blah", fmt.Sprintf(FederationUserPOSTTmpl, "blah", "arn:aws:iam::123456789012:user/blah", test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser1AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusNotFound, fmt.Sprintf(test.GenericResponseTmpl, "Federation user not found.", http.StatusNotFound, appcodes.FederationUserUnknown)},
		{"PUT", FederationUserAPI, true, "/" + test.FedUserArn1, fmt.Sprintf(FederationUserPOSTTmpl, test.FedUserName1, test.FedUserArn1, test.IAMUser1SecretAccessKey, test.IAMUser1SessionToken, test.IAMUser1Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial, test.IAMUser1MFASecret), http.StatusOK, fmt.Sprintf(test.GenericResponseTmpl, "Federation user "+test.FedUserArn1+" updated.", http.StatusOK, appcodes.Info)},
		{"GET", FederationUserAPI, false, "/" + test.FedUserArn1, "", http.StatusOK, fmt.Sprintf(FederationUserResponseTmpl, test.FedUserArn1, test.IAMUser1Expiration, test.IAMUser2AccessKeyId, test.FedUserTTL1, test.IAMUser1MFASerial)},
	}
	// Set the expected database calls that are performed as part of the table tests
	ep[database.StmtKeyFedUserInsert].ExpectExec().WithArgs(test.FedUserArn1, test.FedUserName1, test.FedUserTTL1).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyFedUserInsert].ExpectExec().WithArgs(test.FedUserArn2, test.FedUserName2, test.FedUserTTL2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyFedUserDelete].ExpectExec().WithArgs(test.FedUserArn2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyFedUserInsert].ExpectExec().WithArgs(test.FedUserArn2, test.FedUserName2, test.FedUserTTL2).WillReturnResult(sqlmock.NewResult(0, 1))
	ep[database.StmtKeyFedUserInsert].ExpectExec().WithArgs(test.FedUserArn1, test.FedUserName1, test.FedUserTTL1).WillReturnResult(sqlmock.NewResult(0, 1))

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
	fu, err := federationuser.NewFederationUser(c, test.FedUserArn2)
	if err != nil {
		t.Fatalf("Error testing vault content: %v", err)
	}
	if err := fu.Provider.Read(); err != nil {
		t.Fatalf("Error testing vault content: %v", err)
	}
	//Test backend storage directly
	assert.Equal(t, test.FedUserArn2, fu.ARNString, "ARN not stored as expected")
	assert.Equal(t, test.IAMUser2AccessKeyId, fu.Provider.Credential.AccessKeyId, "ARN not stored as expected")
	assert.Equal(t, test.IAMUser2SessionToken, fu.Provider.Credential.GetSessionToken(), "SessionToken not stored as expected")
	assert.Equal(t, test.IAMUser2SecretAccessKey, fu.Provider.Credential.GetSecretAccessKey(), "SecretAccessKey not stored as expected")
	et, _ := time.Parse(time.RFC3339, test.IAMUser2Expiration)
	assert.Equal(t, et, fu.Provider.Credential.Expiration, "Expiration not stored as expected")
	assert.Equal(t, test.IAMUser2MFASerial, fu.Provider.Credential.MFASerialNumber, "MFA serial not stored as expected")
	assert.Equal(t, test.IAMUser2MFASecret, fu.Provider.Credential.GetMFASecret(), "MFA secret not stored as expected")
}
