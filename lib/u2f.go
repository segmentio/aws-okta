package lib

import (
	"fmt"
	"time"

	u2fhost "github.com/marshallbrekka/go-u2fhost"
	log "github.com/sirupsen/logrus"
)

func authenticateU2FRequest(request *u2fhost.AuthenticateRequest, authTimeout int) (*u2fhost.AuthenticateResponse, error) {
	allDevices := u2fhost.Devices()
	// Filter only the devices that can be opened.
	openDevices := []u2fhost.Device{}
	for i, device := range allDevices {
		err := device.Open()
		if err == nil {
			openDevices = append(openDevices, allDevices[i])
			defer func(i int) {
				allDevices[i].Close()
			}(i)
		}
	}

	if authTimeout == 0 {
		authTimeout = 20
	}

	var err error
	var response *u2fhost.AuthenticateResponse
	prompted := false
	timeout := time.After(time.Second * time.Duration(authTimeout))
	interval := time.NewTicker(time.Millisecond * 250)
	defer interval.Stop()
	for {
		if response != nil {
			break
		}
		select {
		case <-timeout:
			log.Infof("Failed to get authentication response after %d seconds", authTimeout)
			break
		case <-interval.C:
			for _, device := range openDevices {
				response, err = device.Authenticate(request)
				if err == nil {
					break
				} else if _, ok := err.(*u2fhost.TestOfUserPresenceRequiredError); ok {
					if !prompted {
						fmt.Println("Touch the flashing U2F device to authenticate...")
					}
					prompted = true
				} else {
					return nil, err
				}
			}
		}
	}
	log.Debugf("Client Data: %s", response.ClientData)
	log.Debugf("Signature Data: %s", response.SignatureData)
	return response, nil
}
