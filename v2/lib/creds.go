package awsokta

import "time"

type AWSCredsMeta struct {
	ExpiresAt time.Time
}

// a copy/extension of https://docs.aws.amazon.com/sdk-for-go/api/aws/credentials/#Value
type AWSCreds struct {
	AWSCredsMeta

	AccessKeyID string

	SecretAccessKey string

	SessionToken string

	/* TODO?
	   ProviderName string
	*/
}
