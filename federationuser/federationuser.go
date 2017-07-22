package federationuser

import (
	"errors"
	"fmt"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/sts"
	"github.com/jcmturner/awsvaultcredsprovider"
)

type FederationUser struct {
	ARNString   string                                    `json:"Arn"`
	Credentials sts.Credentials                           `json:"Credentials"`
	ARN         arn.ARN                                   `json:"-"`
	Provider    *awsvaultcredsprovider.VaultCredsProvider `json:"-"`
}

func NewFederationUser(c *config.Config, arnStr string) (FederationUser, error) {
	a, err := arn.Parse(arnStr)
	if err != nil {
		return FederationUser{}, fmt.Errorf("Problem with federation user's ARN: %v", err)
	}
	if a.Service != "iam" || a.ResourceType != "user" {
		return FederationUser{}, errors.New("Federation user ARN does not indicate an IAM user")
	}
	p, err := awsvaultcredsprovider.NewVaultCredsProvider(arnStr, *c.Vault.Config, *c.Vault.Credentials)
	if err != nil {
		return FederationUser{}, fmt.Errorf("Error creating credentials provider: %v", err)
	}
	return FederationUser{
		ARNString: arnStr,
		ARN:       a,
		Provider:  p,
	}, nil
}

func (u *FederationUser) SetCredentials(accessKey, secretKey string, TTL int64, MFASerialNumber, MFASecret string) {
	u.Provider.SetSecretAccessKey(secretKey).SetAccessKey(accessKey).SetTTL(TTL)
	if MFASerialNumber != "" && MFASecret != "" {
		u.Provider.WithMFA(MFASerialNumber, MFASecret)
	}
	u.Credentials.AccessKeyID = accessKey
	u.Credentials.SecretAccessKey = "REDACTED"
}

func (u *FederationUser) Store() error {
	if u.Provider == nil {
		return errors.New("Provider not defined, cannot store credentials")
	}
	if u.Provider.Credential.AccessKeyId == "" {
		return errors.New("User does not have credentials defined to be stored")
	}
	return u.Provider.Store()
}

func (u *FederationUser) Load() error {
	if u.Provider == nil {
		return errors.New("Provider not defined, cannot load credentials")
	}
	if err := u.Provider.Read(); err != nil {
		return err
	}
	u.Credentials.AccessKeyID = u.Provider.Credential.AccessKeyId
	u.Credentials.SecretAccessKey = "REDACTED"
	u.Credentials.Expiration = u.Provider.Credential.Expiration
}
