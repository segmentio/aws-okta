package mfa

import (
	"fmt"

	"github.com/segmentio/aws-okta/v2/lib/oktaclient/internal/marshal"
	"github.com/segmentio/aws-okta/v2/lib/oktaclient/internal/mfa/internal/duoclient"
	log "github.com/sirupsen/logrus"
)

type ErrUnknownStatus struct {
	Status string
}

func (e *ErrUnknownStatus) Error() string {
	return fmt.Sprintf("unknown status %s", e.Status)
}

// DUODevice is implementation of MFADevice for SMS
type DUODevice struct {
	challengeCompleted bool
	DeviceName         string
}

// Supported will check if the mfa config can be used by this device
func (d *DUODevice) Supports(factorType, factorProvider string) bool {
	// more details: https://developer.okta.com/docs/reference/api/factors/#factor-type
	return factorType == "web" && factorProvider == "DUO"
}

// Verify is called to get generate the payload that will be sent to Okta.
//   We will call this twice, once to tell Okta to send the code then
//   Once to prompt the user using `CodeSupplier` for the code.
func (d *DUODevice) Verify(authResp marshal.UserAuthn) (string, interface{}, error) {
	var err error

	if authResp.Status == "MFA_CHALLENGE" && !d.challengeCompleted {
		f := authResp.Embedded.Factor
		log.WithFields(log.Fields{
			"host":        f.Embedded.Verification.Host,
			"signature":   f.Embedded.Verification.Signature,
			"state_token": authResp.StateToken,
		}).Trace("DUO MFA_CHALLENGE verify")
		duoClient := &duoclient.DuoClient{
			Host:      f.Embedded.Verification.Host,
			Signature: f.Embedded.Verification.Signature,
			Callback:  f.Embedded.Verification.Links.Complete.Href,
			// TODO: This could be wrong.
			Device:     d.DeviceName,
			StateToken: authResp.StateToken,
		}

		// TODO: safe to assume this is a push notification?
		log.Info("Sending DUO Push Notification...")
		err = duoClient.ChallengeU2f(f.Embedded.Verification.Host)
		if err != nil {
			return "", nil, fmt.Errorf("challenging U2F: %w", err)
		}
		d.challengeCompleted = true
	} else if authResp.Status == marshal.UserAuthnStatusMFARequired || d.challengeCompleted {
		// no action is required other than returning a payload that contains the stateToken
		log.Trace("MFA_REQUIRED verify")
	} else {
		return "", nil, &ErrUnknownStatus{Status: authResp.Status}
	}

	payload := &Payload{
		StateToken: authResp.StateToken,
	}
	return ActionVerify, payload, err
}
