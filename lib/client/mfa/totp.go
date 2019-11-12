package mfa

import (
	"encoding/json"
	"fmt"

	"github.com/segmentio/aws-okta/lib/client/types"
)

// TOTPDevice is the implementation of MFADevice
type TOTPDevice struct {
	userInput Input
	id        string
}

func (d *TOTPDevice) SetId(id string) {
	d.id = id
}

func (d *TOTPDevice) GetId() string {
	return d.id
}

// Supported will return no error if this MFAConfig can be used with this device implementaion
func (d *TOTPDevice) Supported(factor types.OktaUserAuthnFactor) error {
	if factor.FactorType == "token:software:totp" || factor.FactorType == "token:hardware" {
		return nil
	}
	return fmt.Errorf("sms doesn't support %s %w", factor.FactorType, types.ErrNotSupported)
}

// Verify will prompt the user for a code then return the payload for verification
func (d *TOTPDevice) Verify(authResp types.OktaUserAuthn) ([]byte, error) {
	code, err := d.userInput.CodeSupplier(Config{FactorType: "token"})
	if err != nil {
		return []byte(""), err
	}
	return json.Marshal(basicPayload{
		StateToken: authResp.StateToken,
		PassCode:   code,
	})
}
