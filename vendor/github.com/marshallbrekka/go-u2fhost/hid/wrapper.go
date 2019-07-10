package hid

import (
	"github.com/marshallbrekka/go.hid"
)

type RawHidDevice struct {
	Device *hid.DeviceInfo
	Handle *hid.Device
}

func newRawHidDevice(dev *hid.DeviceInfo) *RawHidDevice {
	return &RawHidDevice{
		Device: dev,
	}
}

func (dev *RawHidDevice) Open() error {
	handle, err := hid.OpenPath(dev.Device.Path)
	if err != nil {
		return err
	}
	dev.Handle = handle
	handle.SetReadWriteNonBlocking(true)
	return nil
}

func (dev *RawHidDevice) Close() {
	if dev.Handle != nil {
		(*dev.Handle).Close()
		dev.Handle = nil
	}
}

func (dev *RawHidDevice) Write(data []byte) (int, error) {
	return dev.Handle.Write(data)
}

func (dev *RawHidDevice) ReadTimeout(response []byte, timeout int) (int, error) {
	return dev.Handle.ReadTimeout(response, timeout)
}
