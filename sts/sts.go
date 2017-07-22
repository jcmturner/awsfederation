package sts

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/federationuser"
	"time"
)

func Federate(c *config.Config, fedUserArn, role, roleSessionName, policy string, duration int64) (*sts.AssumeRoleOutput, error) {
	var p *credentials.Provider
	if fu, ok := c.FedUserCache[fedUserArn]; ok {
		p = fu.Provider
	} else {
		fu, err := federationuser.NewFederationUser(c, fedUserArn)
		if err != nil {
			return err
		}
		c.FedUserCache[fedUserArn] = &fu
		p = fu.Provider
	}
	creds := credentials.NewCredentials(p)
	return AssumeRole(role, roleSessionName, policy, duration, creds)
}

func AssumeRole(role, roleSessionName, policy string, duration int64, creds credentials.Credentials) (*sts.AssumeRoleOutput, error) {
	config := aws.NewConfig().WithCredentials(creds)
	sess := session.Must(session.NewSession(config))
	svc := sts.New(sess)
	ctx := context.Background()
	//TODO configure context timeout

	params := &sts.AssumeRoleInput{}.SetRoleArn(role).
		SetDurationSeconds(duration).
		SetRoleSessionName(roleSessionName)
	if policy != "" {
		params.SetPolicy(policy)
	}
	return svc.AssumeRoleWithContext(ctx, params)
}

type AssumedRole struct {
	AssumedRoleUser struct {
		AssumedRoleID string `json:"AssumedRoleId"`
		Arn           string `json:"Arn"`
	} `json:"AssumedRoleUser"`
	Credentials Credentials `json:"Credentials"`
}

type Credentials struct {
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
	AccessKeyID     string    `json:"AccessKeyId"`
}
