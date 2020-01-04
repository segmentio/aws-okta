package mfa

import (
	"fmt"

	"github.com/segmentio/aws-okta/v2/lib/oktaclient/internal/marshal"
)

// TODO: test

// SMSDevice is implementation of MFADevice for SMS
type SMSDevice struct {
	userInput Input
}

// Supported will check if the mfa config can be used by this device
func (d *SMSDevice) Support(factorType string, factorProvider string) bool {
	return factorType == "sms"
}

// Verify is called to get generate the payload that will be sent to Okta.
//   We will call this twice, once to tell Okta to send the code then
//   Once to prompt the user using `CodeSupplier` for the code.
func (d *SMSDevice) Verify(authResp marshal.UserAuthn) (string, interface{}, error) {
	var code string
	var err error

	if authResp.Status == "MFA_CHALLENGE" {
		code, err = d.userInput.CodeSupplier("sms")
		if err != nil {
			return "", nil, fmt.Errorf("code supplier: %w", err)
		}
	} else if authResp.Status == "MFA_REQUIRED" {
		code = ""
	} else {
		return "", nil, &ErrUnknownStatus{Status: authResp.Status}
	}
	payload := &Payload{
		StateToken: authResp.StateToken,
		PassCode:   code,
	}

	return ActionVerify, payload, nil
}
