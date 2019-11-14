package mfa

import "github.com/segmentio/aws-okta/lib/client/types"

// Input is provided to get input from the user.
type Input interface {
	CodeSupplier(factor Config) (string, error)
}

type Config struct {
	Provider   string  // Which MFA provider to use when presented with an MFA challenge
	FactorType string  // Which of the factor types of the MFA provider to use
	DuoDevice  string  // Which DUO device to use for DUO MFA
	Device     *Device // Which DUO device to use for DUO MFA
	Id         string  // the unique id for the MFA device provided by Okta
}

type Device interface {
	// return nil if this device supports this config.
	// return ErrNotSupported if not supported.
	Supported(factor types.OktaUserAuthnFactor) error

	// accepts the oktaUserAuthn struct does generates a verification payload
	// can be sent to Okta. If the response is MFA_CHALLENGE then Verify is
	// called again.
	Verify(authResp types.OktaUserAuthn) (string, []byte, error)
}
type basicPayload struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode,omitempty"`
}

// DefaultDevices returns all the default MFA devices that are supported.
func DefaultDevices(input Input) []Device {
	var devices []Device

	devices = append(devices, &SMSDevice{userInput: input})
	devices = append(devices, &TOTPDevice{userInput: input})
	devices = append(devices, &FIDODevice{})
	devices = append(devices, &DUODevice{})
	return devices
}
