package sts

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"golang.org/x/net/context"
	"fmt"
	"os"
	"github.com/jcmturner/awsvaultcredsprovider"
	"github.com/jcmturner/awsvaultcredsprovider/vault"
	"github.com/jcmturner/restclient"
)

func store(){
	c := restclient.NewConfig().WithEndPoint(VaultURL)
	vconf := vault.Config{
		SecretsPath:      "/secret/",
		ReSTClientConfig: *c,
	}
	vcreds := vault.Credentials{
		UserID: UserID,
		AppID:  AppID,
	}

	p, err := awsvaultcredsprovider.NewVaultCredsProvider(FederationUserARN, vconf, vcreds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not create provider %v\n", err)
	}
	p.SetSecretAccessKey(SecretKey).SetAccessKey(AccessKey).SetTTL(10).WithMFA(MFASerialNumber, MFASecret)

	// Store
	err = p.Store()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not store %v\n", err)
	}
}

func federate() {
	c := restclient.NewConfig().WithEndPoint(VaultURL)
	vconf := vault.Config{
		SecretsPath:      "/secret/",
		ReSTClientConfig: *c,
	}
	vcreds := vault.Credentials{
		UserID: UserID,
		AppID:  AppID,
	}

	//creds := credentials.NewStaticCredentials(AccessKey, SecretKey, "")
	p, err := awsvaultcredsprovider.NewVaultCredsProvider(FederationUserARN, vconf, vcreds)
	creds := credentials.NewCredentials(p)

	config := aws.NewConfig().
		WithRegion("eu-west-1").
		WithCredentials(creds)

	sess := session.Must(session.NewSession(config))
	svc := sts.New(sess)
	ctx := context.Background()

	params := &sts.AssumeRoleInput{}
	params.SetDurationSeconds(AssumedDuration).
		SetRoleArn(AssumedRoleARN).
		SetRoleSessionName(RoleSessionId)

	result, err := svc.AssumeRoleWithContext(ctx, params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "Federated credentials: %+v\n", result.Credentials)
	}


	result, err = svc.AssumeRoleWithContext(ctx, params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "Federated credentials: %+v\n", result.Credentials)
	}
}