package federationuser

import (
	"errors"
	"fmt"
	"github.com/jcmturner/awsfederation/arn"
	"github.com/jcmturner/awsfederation/awscredential"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsvaultcredsprovider"
	"time"
)

const (
	FedUserARNFormat = "arn:aws:iam::%s:user/%s"
)

type FederationUser struct {
	Name            string                                    `json:"Name"`
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

func NewFederationUser(c *config.Config, arn string) (FederationUser, error) {
	a, err := ValidateFederationUserARN(arn)
	if err != nil {
		return FederationUser{}, err
	}
	p, err := awsvaultcredsprovider.NewVaultCredsProvider(arn, *c.Vault.Config, *c.Vault.Credentials)
	if err != nil {
		return FederationUser{}, fmt.Errorf("Error creating credentials provider: %v", err)
	}
	return FederationUser{
		ARNString: arn,
		ARN:       a,
		Provider:  p,
	}, nil
}

func LoadFederationUser(c *config.Config, arn string) (FederationUser, error) {
	u, err := NewFederationUser(c, arn)
	if err != nil {
		return u, err
	}
	err = u.Load()
	return u, err
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

func (u *FederationUser) SetCredentials(accessKey, secretKey string, sessionToken string, exp time.Time, TTL int64, MFASerialNumber, MFASecret string) {
	u.Provider.SetAccessKey(accessKey).SetSecretAccessKey(secretKey).SetSessionToken(sessionToken).SetExpiration(exp).SetTTL(TTL)
	if MFASerialNumber != "" && MFASecret != "" {
		u.Provider.WithMFA(MFASerialNumber, MFASecret)
	}
	u.Credentials.AccessKeyID = accessKey
	u.Credentials.SecretAccessKey = "REDACTED"
}

func (u *FederationUser) SetName(name string) *FederationUser {
	u.Name = name
	u.Provider.Name = name
	return u
}

func (u *FederationUser) Store(stmtMap database.StmtMap) error {
	if u.Provider == nil {
		return errors.New("Provider not defined, cannot store credentials")
	}
	if u.Provider.Credential.AccessKeyId == "" {
		return errors.New("User does not have credentials defined to be stored")
	}
	err := u.Provider.Store()
	if err != nil {
		return err
	}
	if stmt, ok := stmtMap[database.StmtKeyFedUserInsert]; ok {
		_, err := stmt.Exec(u.ARNString)
		if err != nil {
			return err
		}
		return nil
	}
	return errors.New("Prepared statement for DB authorization check not found")
}

func (u *FederationUser) Load() error {
	if u.Provider == nil {
		return errors.New("Provider not defined, cannot load credentials")
	}
	if err := u.Provider.Read(); err != nil {
		return err
	}
	u.Name = u.Provider.Name
	u.Credentials.AccessKeyID = u.Provider.Credential.AccessKeyId
	u.Credentials.SecretAccessKey = "REDACTED"
	u.Credentials.Expiration = u.Provider.Credential.Expiration
	u.Credentials.SessionToken = "REDACTED"
	if u.Provider.Credential.MFASerialNumber != "" {
		u.MFASerialNumber = u.Provider.Credential.MFASerialNumber
		u.MFASecret = "REDACTED"
	}
	u.TTL = u.Provider.Credential.TTL
	return nil
}

func (u *FederationUser) Delete(stmtMap database.StmtMap) error {
	if u.Provider == nil {
		return errors.New("Provider not defined, cannot delete credentials")
	}
	if stmt, ok := stmtMap[database.StmtKeyFedUserDelete]; !ok {
		return errors.New("Prepared statement for DB authorization check not found")
	} else {
		r, err := stmt.Exec(u.ARNString)
		if err != nil {
			return err
		}
		if i, _ := r.RowsAffected(); i != 1 {
			return fmt.Errorf("Expected 1 and only 1 row to be affected. Number affected was: %v", i)
		}
	}
	return u.Provider.Delete()
}

type FedUserCache map[string]*FederationUser
