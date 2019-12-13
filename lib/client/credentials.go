package client

import "fmt"

// type: OktaCredential struct stores Okta credentials and domain information that will
// be used by OktaClient when making API calls to Okta
type OktaCredential struct {
	Username string
	Password string
	Domain   string
	MFA      MFAConfig
}

type MFAConfig struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
	Id         string // the unique id for the MFA device provided by Okta
}

// Checks the validity of OktaCredential and should be called before
// using the credentials to make API calls.
//
// This public method will only validate that credentials exist, it will NOT
// validate them for correctness. To validate correctness an OktaClient must be
// used to make a request to Okta.
func (c *OktaCredential) Validate() error {
	errorReasonString := ""
	if c.Username == "" {
		errorReasonString = "Username must be set.\n"
	}
	if c.Password == "" {
		errorReasonString += "Password must be set.\n"
	}
	if c.Domain == "" {
		errorReasonString += "Domain must be set.\n"
	}

	if errorReasonString == "" {
		return nil
	} else {
		return fmt.Errorf("%v %w", errorReasonString, ErrInvalidCredentials)
	}
}
