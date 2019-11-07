package client

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
)

// Will fetch your Okta username, password, and domain from your keyring secret
// backend.
//
// Will get the default credentials stored under the `okta-creds` key.
//
// feat-request: add support for getting additional sets of credentials.
// The interface for this functionality needs to be defined, it's
// possible to then implement alternative credential backends
// to flexibly support alternative implementations.
func GetOktaCredentialFromKeyring(kr keyring.Keyring) (OktaCredential, error) {
	var oktaCreds OktaCredential

	item, err := kr.Get("okta-creds")
	if err != nil {
		return oktaCreds, err
	}

	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return oktaCreds, fmt.Errorf("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}
	return oktaCreds, nil
}

// looks up the okta domain based on the region. For example, the okta domain
// for "us" is `okta.com` making your api domain as `<your-org>.okta.com`
func GetOktaDomain(region string) (string, error) {
	switch region {
	case "us":
		return OktaServerUs, nil
	case "emea":
		return OktaServerEmea, nil
	case "preview":
		return OktaServerPreview, nil
	}
	return "", fmt.Errorf("invalid region %s", region)
}

// Validates the provided MFA config matches what the user has configured in
// Okta. If the provided config doesn't match an error will be returned.
func selectMFADeviceFromConfig(mfaConfig MFAConfig, factors []oktaUserAuthnFactor) (*oktaUserAuthnFactor, error) {
	log.Debugf("MFAConfig: %v\n", mfaConfig)
	if mfaConfig.Provider == "" || mfaConfig.FactorType == "" {
		return nil, nil
	}

	for _, f := range factors {
		log.Debugf("%v\n", f)
		if strings.EqualFold(f.Provider, mfaConfig.Provider) && strings.EqualFold(f.FactorType, mfaConfig.FactorType) {
			log.Debugf("Using matching factor \"%v %v\" from config\n", f.Provider, f.FactorType)
			return &f, nil
		}
	}

	return nil, fmt.Errorf("Failed to select MFA device with Provider = \"%s\", FactorType = \"%s\"", mfaConfig.Provider, mfaConfig.FactorType)
}

// gets the factor ID that uniquely identifies an MFA device.
func getFactorId(f *oktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	case "token":
		if f.Provider == "SYMANTEC" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor token not supported", f.Provider)
		}
	case "token:software:totp":
		id = f.Id
	case "token:hardware":
		id = f.Id
	case "sms":
		id = f.Id
	case "u2f":
		id = f.Id
	case "push":
		if f.Provider == "OKTA" || f.Provider == "DUO" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor push not supported", f.Provider)
		}
	default:
		err = fmt.Errorf("factor %s not supported", f.FactorType)
	}
	return
}
