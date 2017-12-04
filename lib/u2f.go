package lib

import (
	"time"

	u2f "github.com/Pryz/go-u2fhost"
	log "github.com/Sirupsen/logrus"
)

func authenticateHelper(req *u2f.AuthenticateRequest, devices []*u2f.HidDevice) *u2f.AuthenticateResponse {
	openDevices := []u2f.Device{}

	log.Debugf("Authenticating with request : %+v", req)
	log.Debugf("Found %d device(s)", len(devices))

	for i, device := range devices {
		err := device.Open()
		if err != nil {
			log.Warnf("Failed opening device : %s", err)
		}
		openDevices = append(openDevices, u2f.Device(devices[i]))
		defer func(i int) {
			devices[i].Close()
		}(i)
		version, err := device.Version()
		if err != nil {
			log.Debugf("Device version error: %s", err.Error())
		} else {
			log.Debugf("Device version: %s", version)
		}
	}

	if len(openDevices) == 0 {
		log.Fatalf("Failed to find any devices")
	}

	timeout := time.After(time.Second * 25)
	interval := time.NewTicker(time.Millisecond * 250)
	defer interval.Stop()

	log.Infof("Touch the flashing U2F device to authenticate...")
	for {
		select {
		case <-timeout:
			log.Debug("Failed to get authentication response after 25 seconds")
			return nil
		case <-interval.C:
			for _, device := range openDevices {
				response, err := device.Authenticate(req)
				if err == nil {
					return response
				} else {
					log.Debugf("Got status response %s", err)
				}
			}
		}
	}

	return nil
}
