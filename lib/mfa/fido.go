package mfa

import (
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	u2fhost "github.com/marshallbrekka/go-u2fhost"
)

const (
	MaxOpenRetries = 10
	RetryDelayMS   = 200 * time.Millisecond
)

var (
	errNoDeviceFound = fmt.Errorf("no U2F devices found. device might not be plugged in")
)

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
		return nil, errors.New("No Device Found")
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

	d.Device.Open()

	defer func() {
		d.Device.Close()
	}()
	defer interval.Stop()
	for {
		select {
		case <-timeout:
			return nil, errors.New("Failed to get authentication response after 25 seconds")
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
