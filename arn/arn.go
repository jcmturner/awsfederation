// Package arn provides utilities for manipulating Amazon Resource Names: http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
package arn

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

//arn:partition:service:region:account-id:resource
//arn:partition:service:region:account-id:resourcetype/resource
//arn:partition:service:region:account-id:resourcetype:resource

var Regions = []string{
	"us-east-2",
	"us-east-1",
	"us-west-1",
	"us-west-2",
	"ca-central-1",
	"ap-south-1",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"sa-east-1",
}

type ARN struct {
	Partition    string
	Service      string
	Region       string
	AccountID    string
	ResourceType string
	resourceSep  string
	Resource     string
}

func Parse(arn string) (ARN, error) {
	if !Valid(arn) {
		return ARN{}, errors.New("ARN not valid")
	}
	parts := strings.SplitN(arn, ":", 6)
	a := ARN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		AccountID: parts[4],
	}
	if strings.Contains(parts[5], ":") {
		r := strings.SplitN(arn, ":", 2)
		a.ResourceType = r[0]
		a.resourceSep = ":"
		a.Resource = r[1]
	} else if strings.Contains(parts[5], "/") {
		r := strings.SplitN(arn, "/", 2)
		a.ResourceType = r[0]
		a.resourceSep = "/"
		a.Resource = r[1]
	} else {
		a.Resource = parts[5]
	}
	return a, nil
}

func (a *ARN) String() string {
	r := a.Resource
	if a.resourceSep != "" {
		r = a.ResourceType + a.resourceSep + a.Resource
	}
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s",
		a.Partition,
		a.Service,
		a.Region,
		a.AccountID,
		r,
	)
}

func Valid(arn string) bool {
	if strings.Contains(arn, " ") {
		return false
	}
	if strings.Count(arn, ":") < 5 {
		return false
	}
	parts := strings.SplitN(arn, ":", 6)
	// 2nd field must be "aws" or start "aws-"
	if !strings.HasPrefix(parts[1], "aws-") && parts[1] != "aws" {
		return false
	}
	// 3rd field must not be null
	if parts[2] == "" {
		return false
	}
	// 4th valid region or null or *
	if !ValidRegion(parts[3]) && parts[3] != "" && parts[3] != "*" {
		return false
	}
	// 5th account number (12 digit) or null or *
	if utf8.RuneCountInString(parts[4]) != 12 && parts[4] != "*" {
		return false
	}
	if _, err := strconv.Atoi(parts[4]); err != nil {
		return false
	}
	return strings.HasPrefix(arn, "arn:")
}

func ValidRegion(region string) bool {
	for _, r := range Regions {
		if region == r {
			return true
		}
	}
	return false
}
