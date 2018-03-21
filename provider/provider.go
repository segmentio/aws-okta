package provider

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mulesoft-labs/aws-keycloak/provider/saml"
)

type Provider struct {
	P *KeycloakProvider
	A *AwsProvider
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

func (c *Provider) Retrieve(awsrole string) (sts.Credentials, string, error) {
	log.Debug("Step 0: Checking existing AWS session")
	creds, err := c.A.checkAlreadyAuthd(awsrole)
	if err == nil {
		log.Debugf("AWS session already valid for %s", awsrole)
		return creds, awsrole, nil
	}

	newCreds := c.P.retrieveKeycloakCreds()

	log.Debug("Step 1: Auth to Keycloak")
	err = c.P.basicAuth()
	if err != nil {
		return sts.Credentials{}, "", fmt.Errorf("Failed to authenticate with keycloak: %s", err)
	}

	log.Debug("Step 2: Get SAML form Keycloak")
	assertion, err := c.P.getSamlAssertion()
	if err != nil {
		return sts.Credentials{}, "", err
	}

	roles, principals, _, err := GetRolesFromSAML(assertion.Resp)
	if err != nil {
		return sts.Credentials{}, "", err
	}
	awsshortrole, n := PromptMultiMatchRole(roles, awsrole)

	log.Debug("Step 3: Use SAML to assume AWS role")
	fmt.Printf("Assuming role '%s' (you can use this with the --profile flag to automatically select the role)\n", awsshortrole)
	creds, err = c.A.assumeRoleWithSAML(principals[n], roles[n], string(assertion.RawData))
	if err != nil {
		log.WithField("role", awsshortrole).Errorf("error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, "", err
	} else {
		log.WithField("role", awsshortrole).Info("Successfully assumed role with SAML")
	}

	// Save keycloak creds since auth was successful
	if newCreds {
		c.P.storeKeycloakCreds()
	}

	c.A.storeAwsCreds(creds, awsshortrole)

	return creds, awsshortrole, err
}
