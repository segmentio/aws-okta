package oktaclient

import "github.com/segmentio/aws-okta/v2/lib/oktaclient/internal/marshal"

type MFAConfigDUO struct {
	DeviceName string
}

var defaultMFAConfigDUO = MFAConfigDUO{
	DeviceName: "phone1",
}

// TODO: more

type mfaDevice interface {
	// Supports returns true if this device supports this (type, provider)
	Supports(factorType string, factorProvider string) bool

	// Verify may be called repeatedly to advance the state of the auth flow
	// payload must be JSON-marshallable
	Verify(authResp marshal.UserAuthn) (action string, payload interface{}, err error)
}
