package provider

import (
	"fmt"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mulesoft-labs/aws-keycloak/provider/saml"
)

type Provider struct {
	K *KeycloakProvider
	A *AwsProvider
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

func (p *Provider) Retrieve(awsrole string) (sts.Credentials, string, error) {
	log.Debug("Step 0: Checking existing AWS session")
	creds, err := p.A.checkAlreadyAuthd(awsrole)
	if err == nil {
		log.Debugf("AWS session already valid for %s", awsrole)
		return creds, awsrole, nil
	}

	newCreds := p.K.retrieveKeycloakCreds()

	log.Debug("Step 1: Auth to Keycloak")
	err = p.K.basicAuth()
	if err != nil {
		return sts.Credentials{}, "", fmt.Errorf("Failed to authenticate with keycloak: %s", err)
	}

	log.Debug("Step 2: Get SAML form Keycloak")
	assertion, err := p.K.getSamlAssertion()
	if err != nil {
		return sts.Credentials{}, "", err
	}

	roles, principals, _, err := GetRolesFromSAML(assertion.Resp)
	if err != nil {
		return sts.Credentials{}, "", err
	}
	awsshortrole, n := PromptMultiMatchRole(roles, awsrole)

	log.Debug("Step 3: Use SAML to assume AWS role")
	fmt.Printf("Assuming role '%s'\n", awsshortrole)
	fmt.Printf("  You can specify this role with the --profile flag if you also put it in your aws config.\n")
	fmt.Printf("  Run `aws --profile %s configure` and don't enter any Key ID or Secret Key.\n", awsshortrole)
	creds, err = p.A.assumeRoleWithSAML(principals[n], roles[n], string(assertion.RawData))
	if err != nil {
		log.WithField("role", awsshortrole).Errorf("error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, "", err
	} else {
		log.WithField("role", awsshortrole).Info("Successfully assumed role with SAML")
	}

	// Save keycloak creds since auth was successful
	if newCreds {
		p.K.storeKeycloakCreds()
	}

	p.A.storeAwsCreds(creds, awsshortrole)

	return creds, awsshortrole, err
}
