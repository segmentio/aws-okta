package mfa

import (
	"encoding/json"
	"fmt"

	"github.com/segmentio/aws-okta/lib/client/types"
)

// SMSDevice is implementation of MFADevice for SMS
type SMSDevice struct {
	userInput Input
}

// Supported will check if the mfa config can be used by this device
func (d *SMSDevice) Supported(factor Config) error {
	if factor.FactorType == "sms" {
		return nil
	}
	return fmt.Errorf("sms doesn't support %s %w", factor.FactorType, types.ErrNotSupported)
}

// Verify is called to get generate the payload that will be sent to Okta.
//   We will call this twice, once to tell Okta to send the code then
//   Once to prompt the user using `CodeSupplier` for the code.
func (d *SMSDevice) Verify(authResp types.OktaUserAuthn) (string, []byte, error) {
	var code string
	var err error

	if authResp.Status == "MFA_REQUIRED" {
		code, err = d.userInput.CodeSupplier(Config{FactorType: "sms"})
		if err != nil {
			return "", []byte(""), err
		}
	} else if authResp.Status == "MFA_CHALLENGE" {
		code = ""
	} else {
		return "", []byte{}, fmt.Errorf("Unknown status: %s", authResp.Status)
	}
	payload, err := json.Marshal(basicPayload{
		StateToken: authResp.StateToken,
		PassCode:   code,
	})

	return "verify", payload, err
}
