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
	codeRequested bool
	id            string
}

func (d *DUODevice) SetId(id string) {
	d.id = id
}

func (d *DUODevice) GetId() string {
	return d.id
}

// Supported will check if the mfa config can be used by this device
func (d *DUODevice) Supported(factor types.OktaUserAuthnFactor) error {
	if factor.FactorType == "u2f" && factor.Provider == "DUO" {
		return nil
	}
	return fmt.Errorf("DUOProvider doesn't support %s %w", factor.FactorType, types.ErrNotSupported)
}

// Verify is called to get generate the payload that will be sent to Okta.
//   We will call this twice, once to tell Okta to send the code then
//   Once to prompt the user using `CodeSupplier` for the code.
func (d *DUODevice) Verify(authResp types.OktaUserAuthn) ([]byte, error) {
	var err error

	if d.codeRequested {
		f := authResp.Embedded.Factor
		duoClient := &lib.DuoClient{
			Host:      f.Embedded.Verification.Host,
			Signature: f.Embedded.Verification.Signature,
			Callback:  f.Embedded.Verification.Links.Complete.Href,
			//This could be wrong.
			Device:     f.FactorType,
			StateToken: authResp.StateToken,
		}

		log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
			f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
			authResp.StateToken)

		log.Debug("challenge u2f")
		log.Info("Sending Push Notification...")
		err = duoClient.ChallengeU2f(f.Embedded.Verification.Host)
		if err != nil {
			return []byte{}, err
		}
	} else {
		d.codeRequested = true
	}

	return json.Marshal(basicPayload{
		StateToken: authResp.StateToken,
	})
}
