package mfa

import (
	"fmt"

	"github.com/segmentio/aws-okta/lib/v2/oktaclient/internal/marshal"
)

// TODO: test

// TOTPDevice is the implementation of MFADevice
type TOTPDevice struct {
	userInput Input
}

func (d *TOTPDevice) Supports(factorType string, factorProvider string) bool {
	return factorType == "token:software:totp" || factorType == "token:hardware"
}

// Verify will prompt the user for a code then return the payload for verification
func (d *TOTPDevice) Verify(authResp marshal.UserAuthn) (string, interface{}, error) {
	code, err := d.userInput.CodeSupplier("token")
	if err != nil {
		return "", nil, fmt.Errorf("code supplier: %w", err)
	}
	payload := &Payload{
		StateToken: authResp.StateToken,
		PassCode:   code,
	}
	return ActionVerify, payload, nil
}
