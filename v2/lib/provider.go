// TODO(nick): think of a better name
package awsokta

import "time"

type AWSCredsMeta struct {
	ExpiresAt   time.Time
	BaseRoleARN string
	Region      string

	// may be blank if role assuming was not needed
	AssumedRoleARN string
}

// a copy/extension of https://docs.aws.amazon.com/sdk-for-go/api/aws/credentials/#Value
type AWSCreds struct {
	AccessKeyID string

	SecretAccessKey string

	SessionToken string

	/* TODO?
	   ProviderName string
	*/

	Meta AWSCredsMeta
}

type AWSCredsProvider struct {
	Region      string
	BaseRoleARN string

	// may be blank if role assuming is not needed
	AssumeRoleARN string
}

// TODO
func (p *AWSCredsProvider) Refresh() (AWSCreds, error) {
	return AWSCreds{
		AccessKeyID:     "NotAnAccessKeyID",
		SecretAccessKey: "NotASecretAccessKey",
		SessionToken:    "NotASessionToken",

		Meta: AWSCredsMeta{
			Region:         p.Region,
			BaseRoleARN:    p.BaseRoleARN,
			AssumedRoleARN: p.AssumeRoleARN,
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		},
	}, nil
}
