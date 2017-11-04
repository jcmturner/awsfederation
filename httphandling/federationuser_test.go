package httphandling

import (
	"fmt"
	"github.com/jcmturner/awsfederation/appcode"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsfederation/test"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	FederationUserAPIPath = "/%s/federastionuser/%s"
)

func TestFederationUserGet(t *testing.T) {
	_, _, _, _, _, s := test.TestEnv(t)
	defer s.Close()

	var tests = []struct {
		Method         string
		Path           string
		PostPayload    string
		HttpCode       int
		ResponseString string
	}{
		{"GET", test.FedUserArn1, "", http.StatusOK, "{\"Name\":\"\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}"},
		{"GET", "", "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\"]}"},
		{"GET", "/" + Test_Arn_Stub, "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\"]}"},
		{"GET", "/arn:aws:iam::123456789012:user/notexist", "", http.StatusNotFound, fmt.Sprintf(MessageTemplateJSON, "Federation user not found.", http.StatusNotFound, appcode.FederationUserUnknown)},
		{"POST", "", "{\"Name\":\"" + Test_FedName + "\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}", http.StatusConflict, fmt.Sprintf(MessageTemplateJSON, "Federation user already exists.", http.StatusConflict, appcode.FederationUserAlreadyExists)},
		{"POST", "" + Test_Arn, "{\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"" + Test_SecretAccessKey2 + "\",\"SessionToken\":\"" + Test_SessionToken2 + "\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"" + Test_MFASecret2 + "\"}", http.StatusMethodNotAllowed, fmt.Sprintf(MessageTemplateJSON, "The POST method cannot be performed against this part of the API", http.StatusMethodNotAllowed, appcode.BadData)},
		{"POST", "", "{\"Name\":\"" + Test_FedName2 + "\",\"Arn\":\"" + Test_Arn2 + "\",\"Credentials\":{\"SecretAccessKey\":\"" + Test_SecretAccessKey2 + "\",\"SessionToken\":\"" + Test_SessionToken2 + "\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"" + Test_MFASecret2 + "\"}", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn2+" created.", http.StatusOK, appcode.Info)},
		{"DELETE", "/" + Test_Arn2, "", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn2+" deleted.", http.StatusNotFound, appcode.Info)},
		{"GET", "/" + Test_Arn2, "", http.StatusNotFound, fmt.Sprintf(MessageTemplateJSON, "Federation user not found.", http.StatusNotFound, appcode.FederationUserUnknown)},
		{"POST", "", "{\"Name\":\"" + Test_FedName2 + "\",\"Arn\":\"" + Test_Arn2 + "\",\"Credentials\":{\"SecretAccessKey\":\"" + Test_SecretAccessKey2 + "\",\"SessionToken\":\"" + Test_SessionToken2 + "\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"" + Test_MFASecret2 + "\"}", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn2+" created.", http.StatusOK, appcode.Info)},
		{"GET", "/" + Test_Arn2, "", http.StatusOK, "{\"Arn\":\"" + Test_Arn2 + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration2 + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":12,\"MFASerialNumber\":\"" + Test_MFASerial2 + "\",\"MFASecret\":\"REDACTED\"}"},
		{"GET", "", "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\",\"" + Test_Arn2 + "\"]}"},
		{"GET", "/" + Test_Arn_Stub, "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn + "\"]}"},
		{"GET", "/" + Test_Arn_Stub2, "", http.StatusOK, "{\"FederationUsers\":[\"" + Test_Arn2 + "\"]}"},
		{"PUT", "/" + Test_Arn_Stub + "/blah", "{\"Name\":\"" + Test_FedName + "\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}", http.StatusNotFound, fmt.Sprintf(MessageTemplateJSON, "Federation user not found.", http.StatusNotFound, appcode.FederationUserUnknown)},
		{"PUT", "/" + Test_Arn, "{\"Name\":\"" + Test_FedName + "\",\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}", http.StatusOK, fmt.Sprintf(MessageTemplateJSON, "Federation user "+Test_Arn+" updated.", http.StatusNotFound, appcode.Info)},
		{"GET", "/" + Test_Arn, "", http.StatusOK, "{\"Arn\":\"" + Test_Arn + "\",\"Credentials\":{\"SecretAccessKey\":\"REDACTED\",\"SessionToken\":\"REDACTED\",\"Expiration\":\"" + Test_Expiration + "\",\"AccessKeyId\":\"" + Test_AccessKeyId2 + "\"},\"TTL\":0,\"MFASerialNumber\":\"\",\"MFASecret\":\"\"}"},
	}
	for _, test := range tests {
		t.Logf("Test %s %s\n", test.Method, test.Path)
		request, _ := http.NewRequest(test.Method, fmt.Sprintf(FederationUserAPIPath, APIVersion, test.Path), strings.NewReader(test.PostPayload))
		response := httptest.NewRecorder()
		s.
		a.Router.ServeHTTP(response, request)
		assert.Equal(t, test.HttpCode, response.Code, fmt.Sprintf("Expected HTTP code: %d got: %d (%s %s)", test.HttpCode, response.Code, test.Method, test.Path))
		assert.Equal(t, test.ResponseString, response.Body.String(), fmt.Sprintf("Response not as expected (%s %s)", test.Method, test.Path))
	}
	fu, err := federationuser.NewFederationUser(a.Config, Test_Arn2)
	if err != nil {
		t.Fatalf("Error testing vault content: %v", err)
	}
	if err := fu.Provider.Read(); err != nil {
		t.Fatalf("Error testing vault content: %v", err)
	}
	//Test backend storage directly
	assert.Equal(t, Test_Arn2, fu.ARNString, "ARN not stored as expected")
	assert.Equal(t, Test_AccessKeyId2, fu.Provider.Credential.AccessKeyId, "ARN not stored as expected")
	assert.Equal(t, Test_SessionToken2, fu.Provider.Credential.GetSessionToken(), "SessionToken not stored as expected")
	assert.Equal(t, Test_SecretAccessKey2, fu.Provider.Credential.GetSecretAccessKey(), "SecretAccessKey not stored as expected")
	et, _ := time.Parse(time.RFC3339, Test_Expiration2)
	assert.Equal(t, et, fu.Provider.Credential.Expiration, "Expiration not stored as expected")
	assert.Equal(t, Test_MFASerial2, fu.Provider.Credential.MFASerialNumber, "MFA serial not stored as expected")
	assert.Equal(t, Test_MFASecret2, fu.Provider.Credential.GetMFASecret(), "MFA secret not stored as expected")

}
