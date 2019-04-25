package provider

import (
	"fmt"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mulesoft-labs/aws-keycloak/provider/saml"
)

// Package level vars
var (
	ProviderIn  io.Reader = os.Stdin
	ProviderOut io.Writer = os.Stdout
	ProviderErr io.Writer = os.Stderr
)

type Provider struct {
	K KeycloakProviderIf
	A AwsProviderIf
}

func (p *Provider) List() (roles []string, err error) {
	log.Debug("Step 1: Auth to Keycloak")
	err = p.K.BrowserAuth()
	if err != nil {
		return
	}

	log.Debug("Step 2: Get SAML from Keycloak")
	assertion, err := p.K.GetSamlAssertion()
	if err != nil {
		return
	}

	rps, _, err := saml.GetRolesFromSAML(assertion.Resp)
	if err != nil {
		return
	}

	return saml.RolesOf(rps), nil
}

func (p *Provider) Retrieve(awsrole string) (sts.Credentials, string, error) {
	log.Debugf("Step 0: Checking existing AWS session for %s", awsrole)
	creds, err := p.A.CheckAlreadyAuthd(awsrole)
	if err == nil {
		log.Debugf("AWS session already valid for %s", awsrole)
		return creds, awsrole, nil
	}

	log.Debug("Step 1: Auth to Keycloak")
	err = p.K.BrowserAuth()
	/** Basic auth is deprecated
	newCreds := p.K.RetrieveKeycloakCreds()
	err = p.K.BasicAuth()
	*/
	if err != nil {
		return sts.Credentials{}, "", fmt.Errorf("Failed to authenticate with keycloak: %s", err)
	}

	log.Debug("Step 2: Get SAML from Keycloak")
	assertion, err := p.K.GetSamlAssertion()
	if err != nil {
		return sts.Credentials{}, "", err
	}

	rps, _, err := saml.GetRolesFromSAML(assertion.Resp)
	if err != nil {
		return sts.Credentials{}, "", err
	}
	awsshortrole, n := PromptMultiMatchRole(saml.RolesOf(rps), awsrole)

	log.Debug("Step 3: Use SAML to assume AWS role")
	if awsrole == "" {
		log.Infof("Assuming role '%s'. You can specify this with the --profile flag", awsshortrole)
	}
	creds, err = p.A.AssumeRoleWithSAML(rps[n], string(assertion.RawResp))
	if err != nil {
		if err.(awserr.Error).Code() == sts.ErrCodeExpiredTokenException {
			log.Errorf("You took too long to pick a role")
		} else {
			log.Errorf("Error assuming role with SAML")
		}
		return sts.Credentials{}, "", err
	} else {
		log.WithField("role", awsshortrole).Debug("Successfully assumed role with SAML")
	}

	/** Used when doing BasicAuth
	// Save keycloak creds since auth was successful
	if newCreds {
		p.K.StoreKeycloakCreds()
	}
	*/

	p.A.StoreAwsCreds(creds, awsshortrole)

	return creds, awsshortrole, err
}
