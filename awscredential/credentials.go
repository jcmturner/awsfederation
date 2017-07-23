package awscredential

import "time"

type Credentials struct {
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
	AccessKeyID     string    `json:"AccessKeyId"`
}
