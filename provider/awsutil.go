package provider

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	awsDuration = 3600
)

type AwsProvider struct {
	Keyring keyring.Keyring
}

func (a *AwsProvider) assumeRoleWithSAML(principal, role, assertion string) (sts.Credentials, error) {
	samlSess := session.Must(session.NewSession())
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(principal),
		RoleArn:         aws.String(role),
		SAMLAssertion:   aws.String(assertion),
		DurationSeconds: aws.Int64(awsDuration),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *samlResp.Credentials, nil
}

func (a *AwsProvider) checkAlreadyAuthd(awsrole string) (sts.Credentials, error) {
	awsSessionKeyName := awskeyname(awsrole)
	item, err := a.Keyring.Get(awsSessionKeyName)
	if err != nil {
		return sts.Credentials{}, err
	}

	log.Debug("found aws session in keyring")
	var creds sts.Credentials
	if err = json.Unmarshal(item.Data, &creds); err != nil {
		return sts.Credentials{}, err
	}

	if time.Now().After(*creds.Expiration) {
		log.Debug("aws credentials exist, but expired")
		return sts.Credentials{}, errors.New("Credentials exist, but expired")
	}
	return creds, nil
}

func (a *AwsProvider) storeAwsCreds(creds sts.Credentials, awsrole string) {
	awsSessionKeyName := awskeyname(awsrole)
	encoded, err := json.Marshal(creds)
	if err != nil {
		log.Debugf("Couldn't marshal aws session... %s", err)
	} else {
		newAwsSessionItem := keyring.Item{
			Key:   awsSessionKeyName,
			Data:  encoded,
			Label: awsSessionKeyName,
			KeychainNotTrustApplication: false,
		}
		if err := a.Keyring.Set(newAwsSessionItem); err != nil {
			log.Debugf("Failed to write aws session to keyring!")
		} else {
			log.Debugf("Successfully stored aws session to keyring!")
		}
	}
}

func awskeyname(awsrole string) string {
	return "aws-session-" + awsrole
}
