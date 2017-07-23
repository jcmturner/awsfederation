package federationuser

import (
	"errors"
	"fmt"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/awscredential"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsvaultcredsprovider"
)

const (
	FedUserARNFormat = "arn:aws:iam::%s:user/%s"
)

type FederationUser struct {
	ARNString       string                                    `json:"Arn"`
	Credentials     awscredential.Credentials                 `json:"Credentials"`
	TTL             int64                                     `json:"TTL"`
	MFASerialNumber string                                    `json:"MFASerialNumber"`
	MFASecret       string                                    `json:"MFASecret"`
	ARN             arn.ARN                                   `json:"-"`
	Provider        *awsvaultcredsprovider.VaultCredsProvider `json:"-"`
}

type FederationUserList struct {
	FederationUsers []string
}

func NewFederationUser(c *config.Config, arnStr string) (FederationUser, error) {
	a, err := ValidateFederationUserARN(arnStr)
	if err != nil {
		return FederationUser{}, err
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

func ValidateFederationUserARN(arnStr string) (arn.ARN, error) {
	a, err := arn.Parse(arnStr)
	if err != nil {
		return a, fmt.Errorf("Problem with federation user's ARN: %v", err)
	}
	if a.Service != "iam" || a.ResourceType != "user" {
		return a, errors.New("Federation user ARN does not indicate an IAM user")
	}
	return a, nil
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
	if u.Provider.Credential.MFASerialNumber != "" {
		u.MFASerialNumber = u.Provider.Credential.MFASerialNumber
		u.MFASecret = "REDACTED"
	}
	u.TTL = u.Provider.Credential.TTL
	return nil
}

func (u *FederationUser) Delete() error {
	if u.Provider == nil {
		return errors.New("Provider not defined, cannot delete credentials")
	}
	return u.Provider.Delete()
}

type FedUserCache map[string]*FederationUser
