package provider

import (
	"strings"
)

const (
	DefaultRegion   = "us-east-1"
	DefaultKeycloak = "id"
)

type Aliases map[string]string

func (as Aliases) Exists(alias string) bool {
	_, exists := as[alias]
	return exists
}

func (as Aliases) Lookup(alias string) (kcprofile, awsrole, region string) {
	s := strings.Split(as[alias], ":")
	kcprofile = s[0]
	awsrole = s[1]
	if len(s) == 3 {
		region = s[2]
	}
	// else region is empty
	return
}
