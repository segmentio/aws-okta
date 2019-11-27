package mfa

import (
	"encoding/json"
	"fmt"

	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/client/types"
	log "github.com/sirupsen/logrus"
)

// DUODevice is implementation of MFADevice for SMS
type DUODevice struct {
	challengeCompleted bool
	duoMFADevice       string
}

// Supported will check if the mfa config can be used by this device
func (d *DUODevice) Supported(factor Config) error {
	// this is the Okta factor type and is always "web" when provider is "DUO"
	// more details: https://developer.okta.com/docs/reference/api/factors/#factor-type
	if factor.FactorType == "web" && factor.Provider == "DUO" {
		return nil
	}
	return fmt.Errorf("DUOProvider doesn't support %s %w", factor.FactorType, types.ErrNotSupported)
}

// Verify is called to get generate the payload that will be sent to Okta.
//   We will call this twice, once to tell Okta to send the code then
//   Once to prompt the user using `CodeSupplier` for the code.
func (d *DUODevice) Verify(authResp types.OktaUserAuthn) (string, []byte, error) {
	var err error

	if authResp.Status == "MFA_CHALLENGE" && !d.challengeCompleted {
		f := authResp.Embedded.Factor
		duoClient := &lib.DuoClient{
			Host:      f.Embedded.Verification.Host,
			Signature: f.Embedded.Verification.Signature,
			Callback:  f.Embedded.Verification.Links.Complete.Href,
			//This could be wrong.
			Device:     d.duoMFADevice,
			StateToken: authResp.StateToken,
		}

		log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
			f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
			authResp.StateToken)

		log.Debug("challenge u2f")
		log.Info("Sending Push Notification...")
		err = duoClient.ChallengeU2f(f.Embedded.Verification.Host)
		if err != nil {
			return "", []byte{}, err
		}
		d.challengeCompleted = true
		// no action is required other than returning a payload that contains the stateToken
	} else if authResp.Status == "MFA_REQUIRED" || d.challengeCompleted {
		//
		log.Debug("MFA_REQUIRED")
	} else {
		return "", []byte{}, fmt.Errorf("unknown status: %s", authResp.Status)
	}

	payload, err := json.Marshal(basicPayload{
		StateToken: authResp.StateToken,
	})
	return "verify", payload, err
}
