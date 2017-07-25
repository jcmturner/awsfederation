package sts

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/jcmturner/awsfederation/awscredential"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsvaultcredsprovider"
)

func Federate(c *config.Config, fc *federationuser.FedUserCache, fedUserArn, role, roleSessionName, policy string, duration int64) (*sts.AssumeRoleOutput, error) {
	var p *awsvaultcredsprovider.VaultCredsProvider
	if fu, ok := (*fc)[fedUserArn]; ok {
		p = fu.Provider
	} else {
		fu, err := federationuser.NewFederationUser(c, fedUserArn)
		if err != nil {
			return &sts.AssumeRoleOutput{}, err
		}
		(*fc)[fedUserArn] = &fu
		p = fu.Provider
	}
	creds := credentials.NewCredentials(p)
	return AssumeRole(role, roleSessionName, policy, duration, creds)
}

func AssumeRole(role, roleSessionName, policy string, duration int64, creds *credentials.Credentials) (*sts.AssumeRoleOutput, error) {
	config := aws.NewConfig().WithCredentials(creds)
	sess := session.Must(session.NewSession(config))
	svc := sts.New(sess)
	ctx := context.Background()
	//TODO configure context timeout

	var params *sts.AssumeRoleInput
	params.SetRoleArn(role).
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
	Credentials awscredential.Credentials `json:"Credentials"`
}
