# Notice: this is forked from [GeertJohan/hid.go](https://github.com/GeertJohan/hid.go) just to modify the `cgo.wchar` dependency to include a patch that fixes some issues.

## go.hid
This [go](http://golang.org) package wraps the [signal11/hidapi](https://github.com/signal11/hidapi) and provides communication with USB Human Interface Devices.

**This package is not completely tested yet!**

### Installation:
This project depends on libhidapi, which must be installed manually.
```shell
git clone git@github.com:signal11/hidapi.git
cd hidapi
./bootstrap
./configure
```

Now change directory depending on your OS. 

For linux + hidraw: `cd linux`. (requires libudev. Package libudev-dev on debian/ubuntu.)

For linux + libusb: `cd libusb`. (requires libusb. Package libusb-1.0-0-dev on debian/ubuntu.)

For mac: `cd mac`.

For windows: `cd windows`.

Make and install.
For linux/mac:
```
make
sudo make install
```
For windows:
```
run some wizzard, probably.. (PR on readme is very welcome)
```

Lastly, for linux only:
Create a symlink pointing libhidapi.so to the version you chose:

For linux + hidraw: `cd /usr/local/lib; sudo ln -s libhidapi-hidraw.so libhidapi.so`

For linux + libusb: `cd /usr/local/lib; sudo ln -s libhidapi-libusb.so libhidapi.so`

For more instructions on libhidapi, please visit [signal11/hidapi](https://github.com/signal11/hidapi).

When you have installed hidapi lib, install this package with `go get github.com/GeertJohan/go.hid`.

### Documentation:
[godoc.org/github.com/GeertJohan/go.hid](https://godoc.org/github.com/GeertJohan/go.hid)

### Example:
This is a simple example on how to use feature reports. For a working example view [GeertJohan/mgl](https://github.com/GeertJohan/mgl).
```go
package main

import(
	"log"
	"github.com/GeertJohan/go.hid"
)

func main() {
	// open the MSI GT leds device
	leds, err := hid.Open(0x1770, 0xff00, "")
	if err != nil {
		log.Fatalf("Could not open leds device: %s", err)
	}
	defer leds.Close()

	// create a feature report. This is always 8*n+1 bytes long, where n is >1.
	data := make([]byte, 9)
	data[0] = 0x42  // report ID
	data[1] = 0x00  // dummy data
	data[2] = 0x01  // dummy data
	data[3] = 0x02  // dummy data
	data[4] = 0x03  // dummy data
	data[5] = 0x04  // dummy data
	data[6] = 0x05  // dummy data
	data[7] = 0x06  // dummy data
	data[8] = 0x07  // dummy data

	_, err := leds.SendFeatureReport(data)
	if err != nil {
		log.Fatalf("Could not send feature report to do dummy action. %s\n", err)
	}
}
```

### License:
The go code in this project is licenced under a a Simplified BSD license. Please read the [LICENSE file](LICENSE).

### TODO:
At this point, the package works for linux with hidraw.
hidapi itself is already cross-platform, so making this package work cross-platform shouldn't be a lot of work.
- Make this package work cross-platform.
- Add better support for hidapi init() and exit(). (At this time hidapi's init() is called once on first Open() call)
- Add tests (find if there is a usb-hid dummy device that has expected input/output and works consistently within an OS (we can write a test file for each OS seperated))
- Better example (preferably with a dummy test device)

### History:
I started this project to be able to communicate with the MSI leds device in the MSI GT780DX laptop. For more information about that project, visit [GeertJohan/mgl](https://github.com/GeertJohan/mgl).