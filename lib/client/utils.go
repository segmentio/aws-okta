package client

import (
	"fmt"
)

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
