package mfa

import (
	"fmt"

	"github.com/segmentio/aws-okta/lib/client/types"
)

// Input is provided to get input from the user.
type Input interface {
	CodeSupplier(factor Config) (string, error)
}

type Config struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
	Device     Device // The implementation that interacts with the device
	Id         string // the unique id for the MFA device provided by Okta
}

type Device interface {

	// Supported takes in an mfa.Config object and returns nil if this device can be used with
	// the config. If the device doesn't support this config an error if it can't
	Supported(factor Config) error

	// Verify makes a call out to the implementation for this MFA factor type/provider.
	// the implementation is basically a state machine that uses tmpUserAuthn to determine
	// what the correct state is. Using this verify interfacce to interact with the device means
	// that someone using this client in their own application could in theory implement their own
	// MFA type or re-implement an existing type if there are specific requirements.
	Verify(authResp types.OktaUserAuthn) (string, []byte, error)
}

//basicPayload is a common request body that is sent as part of mfa validation.
// if PassCode is empty string it will be omitted when converted to and byte array.
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

// BuildMFAPath returns a path that okta client can use to make a request to okta
func BuildMFAPath(factorId string, action string) (string, error) {
	path := "api/v1/authn/factors/"

	switch action {
	case "verify":
		path += factorId + "/" + action
	case "cancel":
		path += action
	case "verify/resend":
		path += factorId + action
	default:
		return "", fmt.Errorf("unknown MFA action %s", action)
	}
	return path, nil
}
