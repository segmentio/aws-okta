package mfa

import (
	"errors"
	"fmt"
	"time"

	"github.com/segmentio/aws-okta/lib/v2/oktaclient/internal/marshal"
	log "github.com/sirupsen/logrus"

	u2fhost "github.com/marshallbrekka/go-u2fhost"
)

// TODO: test

const (
	MaxOpenRetries = 10
	RetryDelayMS   = 200 * time.Millisecond
)

var (
	errNoDeviceFound = fmt.Errorf("no U2F devices found")
)

// FIDODevice is implementation of MFADevice for SMS
type FIDODevice struct {
}

func (d *FIDODevice) Supports(factorType string, factorProvider string) bool {
	return factorType == "u2f" && factorProvider == "FIDO"
}

// payload may be a Payload, or a SignedAssertion
func (d *FIDODevice) Verify(authResp marshal.UserAuthn) (string, interface{}, error) {
	var code string

	if authResp.Status == "MFA_CHALLENGE" {
		f := authResp.Embedded.Factor
		fidoClient, err := NewFidoClient(f.Embedded.Challenge.Nonce,
			f.Profile.AppId,
			f.Profile.Version,
			f.Profile.CredentialId,
			authResp.StateToken)
		if err != nil {
			return "", nil, fmt.Errorf("creating FIDO client: %w", err)
		}
		signedAssertion, err := fidoClient.ChallengeU2f()
		if err != nil {
			return "", nil, fmt.Errorf("getting fido signed assertion: %w", err)
		}
		// re-assign the payload to provide U2F responses.
		payload := signedAssertion
		if err != nil {
			return "", nil, err
		}
		return "verify", payload, nil
	} else if authResp.Status == "MFA_REQUIRED" {
		code = ""
	} else {
		return "", nil, &ErrUnknownStatus{Status: authResp.Status}
	}
	payload := Payload{
		StateToken: authResp.StateToken,
		PassCode:   code,
	}

	return ActionVerify, payload, nil
}

type FidoClient struct {
	ChallengeNonce string
	AppId          string
	Version        string
	Device         u2fhost.Device
	KeyHandle      string
	StateToken     string
}

type SignedAssertion struct {
	StateToken    string `json:"stateToken"`
	ClientData    string `json:"clientData"`
	SignatureData string `json:"signatureData"`
}

func NewFidoClient(challengeNonce, appId, version, keyHandle, stateToken string) (FidoClient, error) {
	var device u2fhost.Device
	var err error

	retryCount := 0
	for retryCount < MaxOpenRetries {
		device, err = findDevice()
		if err != nil {
			if err == errNoDeviceFound {
				return FidoClient{}, err
			}

			retryCount++
			time.Sleep(RetryDelayMS)
			continue
		}

		return FidoClient{
			Device:         device,
			ChallengeNonce: challengeNonce,
			AppId:          appId,
			Version:        version,
			KeyHandle:      keyHandle,
			StateToken:     stateToken,
		}, nil
	}

	return FidoClient{}, fmt.Errorf("failed to create client: %s. exceeded max retries of %d", err, MaxOpenRetries)
}

func (d *FidoClient) ChallengeU2f() (*SignedAssertion, error) {

	if d.Device == nil {
		return nil, errors.New("no device found")
	}
	request := &u2fhost.AuthenticateRequest{
		Challenge: d.ChallengeNonce,
		// the appid is the only facet.
		Facet:     d.AppId,
		AppId:     d.AppId,
		KeyHandle: d.KeyHandle,
	}
	// do the change
	prompted := false
	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	var responsePayload *SignedAssertion

	err := d.Device.Open()
	if err != nil {
		return nil, err
	}
	defer func() {
		d.Device.Close()
	}()
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			return nil, errors.New("failed to get authentication response after 25 seconds")
		case <-interval.C:
			response, err := d.Device.Authenticate(request)
			if err == nil {
				responsePayload = &SignedAssertion{
					StateToken:    d.StateToken,
					ClientData:    response.ClientData,
					SignatureData: response.SignatureData,
				}
				fmt.Printf("  ==> Touch accepted. Proceeding with authentication\n")
				return responsePayload, nil
			}

			switch t := err.(type) {
			case *u2fhost.TestOfUserPresenceRequiredError:
				if !prompted {
					fmt.Printf("\nTouch the flashing U2F device to authenticate...\n")
					prompted = true
				}
			default:
				log.Debug("Got ErrType: ", t)
				return responsePayload, err
			}
		}
	}

	return responsePayload, nil
}

func findDevice() (u2fhost.Device, error) {
	var err error

	allDevices := u2fhost.Devices()
	if len(allDevices) == 0 {
		return nil, errNoDeviceFound
	}

	for i, device := range allDevices {
		err = device.Open()
		if err != nil {
			log.Debugf("failed to open device: %s", err)
			device.Close()

			continue
		}

		return allDevices[i], nil
	}

	return nil, fmt.Errorf("failed to open fido U2F device: %s", err)
}
