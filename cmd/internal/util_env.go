package cmd

import (
	"fmt"
	"strings"
	"time"

	awsokta "github.com/segmentio/aws-okta/lib/v2"
)

type kvEnv map[string]string

func (e kvEnv) LoadFromEnviron(kevs ...string) {
	for _, kev := range kevs {
		kv := strings.SplitN(kev, "=", 2)
		if len(kv) != 2 {
			// skip invalid
			continue
		}
		e[kv[0]] = kv[1]
	}
}

func (e kvEnv) Environ() []string {
	r := []string{}
	for k, v := range e {
		r = append(r, fmt.Sprintf("%s=%s", k, v))
	}
	return r
}

func (e kvEnv) AddCreds(creds awsokta.AWSCreds) {
	e["AWS_SESSION_TOKEN"] = creds.SessionToken
	e["AWS_SECURITY_TOKEN"] = creds.SessionToken
	e["AWS_ACCESS_KEY_ID"] = creds.AccessKeyID
	e["AWS_SECRET_ACCESS_KEY"] = creds.SecretAccessKey
}

type infoEnvs struct {
	Region         string
	ProfileName    string
	BaseRoleARN    string
	AssumedRoleARN string
	ExpiresAt      time.Time
}

func (e kvEnv) AddInfo(ie infoEnvs) {
	e["AWS_OKTA_PROFILE"] = ie.ProfileName

	e["AWS_REGION"] = ie.Region
	e["AWS_DEFAULT_REGION"] = ie.Region

	e["AWS_OKTA_BASE_ROLE_ARN"] = ie.BaseRoleARN
	if spl := strings.Split(ie.BaseRoleARN, "/"); len(spl) > 1 {
		e["AWS_OKTA_BASE_ROLE_NAME"] = spl[1]
	}

	if ie.AssumedRoleARN != "" {
		e["AWS_OKTA_ASSUMED_ROLE_ARN"] = ie.AssumedRoleARN
		if spl := strings.Split(ie.AssumedRoleARN, "/"); len(spl) > 1 {
			e["AWS_OKTA_ASSUMED_ROLE_NAME"] = spl[1]
		}
	}
	e["AWS_OKTA_SESSION_EXPIRATION"] = fmt.Sprintf("%d", ie.ExpiresAt.Unix())
}
