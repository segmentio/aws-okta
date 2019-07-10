package hid

/**
 * This code is licensed under a Simplified BSD License. For more information read the LICENSE file that came with this package.
 */

// This file wraps github.com/signall11/hidapi
// It's based on their hidapi.h, which this file also includes and actually wraps.

/*
#cgo linux pkg-config: libusb-1.0
#cgo linux LDFLAGS: -lusb-1.0
#cgo darwin LDFLAGS: -framework IOKit -framework CoreFoundation
#cgo windows LDFLAGS: -lsetupapi
#include "hidapi.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/vitaminwater/cgo.wchar"
)

var errNotImplemented = errors.New("not implemented yet")

//++ FIXME: How to do this on binary end? C.hid_exit()
// wrap as hid.Exit() ???? that sounds bad..

// struct hid_device_;
// typedef struct hid_device_ hid_device; /**< opaque hidapi structure */
type Device struct {
	hidHandle *C.hid_device
}

// /** hidapi info structure */
// struct hid_device_info {
//  /** Platform-specific device path */
//  char *path;
//  /** Device Vendor ID */
//  unsigned short vendor_id;
//  /** Device Product ID */
//  unsigned short product_id;
//  /** Serial Number */
//  wchar_t *serial_number;
//  /** Device Release Number in binary-coded decimal,
//      also known as Device Version Number */
//  unsigned short release_number;
//  /** Manufacturer String */
//  wchar_t *manufacturer_string;
//  /** Product string */
//  wchar_t *product_string;
//  /** Usage Page for this Device/Interface
//      (Windows/Mac only). */
//  unsigned short usage_page;
//  /** Usage for this Device/Interface
//      (Windows/Mac only).*/
//  unsigned short usage;
//  /** The USB interface which this logical device
//      represents. Valid on both Linux implementations
//      in all cases, and valid on the Windows implementation
//      only if the device contains more than one interface. */
//  int interface_number;
//  /** Pointer to the next device */
//  struct hid_device_info *next;
// };

// DeviceInfo provides all information about an HID device.
type DeviceInfo struct {
	Path            string
	VendorId        uint16
	ProductId       uint16
	SerialNumber    string
	ReleaseNumber   uint16
	Manufacturer    string
	Product         string
	UsagePage       uint16 // Only being used with windows/mac, which are not supported by go.hid yet.
	Usage           uint16 // Only being used with windows/mac, which are not supported by go.hid yet.
	InterfaceNumber int
}

// Get actual hid *Device from DeviceInfo object
func (di *DeviceInfo) Device() (*Device, error) {
	return Open(di.VendorId, di.ProductId, di.SerialNumber)
}

// List of DeviceInfo objects
type DeviceInfoList []*DeviceInfo

// /** @brief Initialize the HIDAPI library.
//
//  This function initializes the HIDAPI library. Calling it is not
//  strictly necessary, as it will be called automatically by
//  hid_enumerate() and any of the hid_open_*() functions if it is
//  needed.  This function should be called at the beginning of
//  execution however, if there is a chance of HIDAPI handles
//  being opened by different threads simultaneously.
//
//  @ingroup API
//
//  @returns
//  	This function returns 0 on success and -1 on error.
// */
// int HID_API_EXPORT HID_API_CALL hid_init(void);

var initOnce sync.Once

// Internal use. Called to initialize the C hid library in a threadsafe way.
func hidInit() error {
	var err error

	initFunc := func() {
		errInt := C.hid_init()
		if errInt == -1 {
			err = errors.New("Could not initialize hidapi.")
		}
	}

	initOnce.Do(initFunc)

	return err
}

// /** @brief Finalize the HIDAPI library.
//
//  This function frees all of the static data associated with
//  HIDAPI. It should be called at the end of execution to avoid
//  memory leaks.
//
//  @ingroup API
//
//     @returns
//  	This function returns 0 on success and -1 on error.
// */
// int HID_API_EXPORT HID_API_CALL hid_exit(void);

// TODO
func Exit() error {
	//++ return error?
	//++
	return errNotImplemented
}

// /** @brief Enumerate the HID Devices.
//
//  This function returns a linked list of all the HID devices
//  attached to the system which match vendor_id and product_id.
//  If @p vendor_id is set to 0 then any vendor matches.
//  If @p product_id is set to 0 then any product matches.
//  If @p vendor_id and @p product_id are both set to 0, then
//  all HID devices will be returned.
//
//  @ingroup API
//  @param vendor_id The Vendor ID (VID) of the types of device
//  	to open.
//  @param product_id The Product ID (PID) of the types of
//  	device to open.
//
//     @returns
//     	This function returns a pointer to a linked list of type
//     	struct #hid_device, containing information about the HID devices
//     	attached to the system, or NULL in the case of failure. Free
//     	this linked list by calling hid_free_enumeration().
// */
// struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(unsigned short vendor_id, unsigned short product_id);

// Retrieve a list of DeviceInfo objects that match the given vendorId and productId.
// To retrieve a list of all HID devices': use 0x0 as vendorId and productId.
func Enumerate(vendorId uint16, productId uint16) (DeviceInfoList, error) {
	var err error

	// call C.hid_enumerate with given parameters
	first := C.hid_enumerate(C.ushort(vendorId), C.ushort(productId))

	// check for failure
	if first == nil {
		return nil, errors.New("Could not enumerate devices. Failure.")
	}

	// defer free-ing first
	defer C.hid_free_enumeration(first)

	// make DeviceInfoList to fill
	dil := make(DeviceInfoList, 0)

	// loop over linked list to fill DeviceInfoList
	for next := first; next != nil; next = next.next {

		// create DeviceInfo instance from next hid_device_info
		di := &DeviceInfo{
			Path:            C.GoString(next.path),
			VendorId:        uint16(next.vendor_id),
			ProductId:       uint16(next.product_id),
			ReleaseNumber:   uint16(next.release_number),
			UsagePage:       uint16(next.usage_page),
			Usage:           uint16(next.usage),
			InterfaceNumber: int(next.interface_number),
		}

		// get and convert serial_number from next hid_device_info
		di.SerialNumber, err = wchar.WcharStringPtrToGoString(unsafe.Pointer(next.serial_number))
		if err != nil {
			di.SerialNumber = ""
		}

		// get and convert manufacturer_string from next hid_device_info
		di.Manufacturer, err = wchar.WcharStringPtrToGoString(unsafe.Pointer(next.manufacturer_string))
		if err != nil {
			di.Manufacturer = ""
		}

		// get and convert product_string from next hid_device_info
		di.Product, err = wchar.WcharStringPtrToGoString(unsafe.Pointer(next.product_string))
		if err != nil {
			return nil, fmt.Errorf("Could not convert *C.wchar_t product_string from hid_device_info to go string. Error: %s\n", err)
		}

		// store di in dil
		dil = append(dil, di)
	}

	// all done
	return dil, nil
}

// /** @brief Open a HID device using a Vendor ID (VID), Product ID
//  (PID) and optionally a serial number.
//
//  If @p serial_number is NULL, the first device with the
//  specified VID and PID is opened.
//
//  @ingroup API
//  @param vendor_id The Vendor ID (VID) of the device to open.
//  @param product_id The Product ID (PID) of the device to open.
//  @param serial_number The Serial Number of the device to open
//  	               (Optionally NULL).
//
//  @returns
//  	This function returns a pointer to a #hid_device object on
//  	success or NULL on failure.
// */
// HID_API_EXPORT hid_device * HID_API_CALL hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number);

// Open HID by vendorId, productId and serialNumber.
// SerialNumber is optional and can be empty string ("").
// Returns a *Devica and an error.
func Open(vendorId uint16, productId uint16, serialNumber string) (*Device, error) {
	var err error

	// call hidInit(). hidInit() checks if actual call to hid_hidInit() is required.
	if err = hidInit(); err != nil {
		return nil, err
	}

	// serialNumberWchar value. Default nil.
	serialNumberWcharPtr := (*C.wchar_t)(nil)

	// if a serialNumber is given, create a WcharString and set the pointer to it's first position pointer
	if len(serialNumber) > 0 {
		serialNumberWchar, err := wchar.FromGoString(serialNumber)
		if err != nil {
			return nil, errors.New("Unable to convert serialNumber to WcharString")
		}
		serialNumberWcharPtr = (*C.wchar_t)(unsafe.Pointer(serialNumberWchar.Pointer()))
	}

	// call hid_open()
	hidHandle := C.hid_open(C.ushort(vendorId), C.ushort(productId), serialNumberWcharPtr)

	if hidHandle == nil {
		return nil, errors.New("Unable to open device.")
	}

	dev := &Device{
		hidHandle: hidHandle,
	}

	// done
	return dev, nil
}

// /** @brief Open a HID device by its path name.
//
//  The path name be determined by calling hid_enumerate(), or a
//  platform-specific path name can be used (eg: /dev/hidraw0 on
//  Linux).
//
//  @ingroup API
//     @param path The path name of the device to open
//
//  @returns
//  	This function returns a pointer to a #hid_device object on
//  	success or NULL on failure.
// */
// HID_API_EXPORT hid_device * HID_API_CALL hid_open_path(const char *path);

// Open hid by path.
// Returns a *Device and an error
func OpenPath(path string) (*Device, error) {
	// call hidInit(). hidInit() checks if actual call to hid_hidInit() is required.
	if err := hidInit(); err != nil {
		return nil, err
	}

	// conver given path to CChar
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	// call hid_open_path and check for error
	dev := C.hid_open_path(cPath)
	if dev == nil {
		return nil, errors.New("Could not open device by path.")
	}

	d := &Device{
		hidHandle: dev,
	}

	// all done
	return d, nil
}

// /** @brief Write an Output report to a HID device.
//
//  The first byte of @p data[] must contain the Report ID. For
//  devices which only support a single report, this must be set
//  to 0x0. The remaining bytes contain the report data. Since
//  the Report ID is mandatory, calls to hid_write() will always
//  contain one more byte than the report contains. For example,
//  if a hid report is 16 bytes long, 17 bytes must be passed to
//  hid_write(), the Report ID (or 0x0, for devices with a
//  single report), followed by the report data (16 bytes). In
//  this example, the length passed in would be 17.
//
//  hid_write() will send the data on the first OUT endpoint, if
//  one exists. If it does not, it will send the data through
//  the Control Endpoint (Endpoint 0).
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param data The data to send, including the report number as
//  	the first byte.
//  @param length The length in bytes of the data to send.
//
//  @returns
//  	This function returns the actual number of bytes written and
//  	-1 on error.
// */
// int  HID_API_EXPORT HID_API_CALL hid_write(hid_device *device, const unsigned char *data, size_t length);

// Write data to hid device.
// Implementing the io.Writer interface with this method.
func (dev *Device) Write(b []byte) (n int, err error) {
	// quick return when b is empty
	if len(b) == 0 {
		return 0, nil
	}

	// write data to hid device and handle error
	res := C.hid_write(dev.hidHandle, (*C.uchar)(&b[0]), C.size_t(len(b)))
	resInt := int(res)
	if resInt == -1 {
		return 0, dev.lastError()
	}

	// all done
	return resInt, nil
}

// /** @brief Read an Input report from a HID device with timeout.
//
//  Input reports are returned
//  to the host through the INTERRUPT IN endpoint. The first byte will
//  contain the Report number if the device uses numbered reports.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param data A buffer to put the read data into.
//  @param length The number of bytes to read. For devices with
//  	multiple reports, make sure to read an extra byte for
//  	the report number.
//  @param milliseconds timeout in milliseconds or -1 for blocking wait.
//
//  @returns
//  	This function returns the actual number of bytes read and
//  	-1 on error.
// */
// int HID_API_EXPORT HID_API_CALL hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds);

// Read from hid device with given timeout
func (dev *Device) ReadTimeout(b []byte, timeout int) (n int, err error) {
	// quick return when b is empty
	if len(b) == 0 {
		return 0, nil
	}

	// read data from hid device and handle error
	res := C.hid_read_timeout(dev.hidHandle, (*C.uchar)(&b[0]), C.size_t(len(b)), C.int(timeout))
	resInt := int(res)
	if resInt == -1 {
		return 0, dev.lastError()
	}

	// all done
	return resInt, nil
}

// /** @brief Read an Input report from a HID device.
//
//  Input reports are returned
//     to the host through the INTERRUPT IN endpoint. The first byte will
//  contain the Report number if the device uses numbered reports.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param data A buffer to put the read data into.
//  @param length The number of bytes to read. For devices with
//  	multiple reports, make sure to read an extra byte for
//  	the report number.
//
//  @returns
//  	This function returns the actual number of bytes read and
//  	-1 on error.
// */
// int  HID_API_EXPORT HID_API_CALL hid_read(hid_device *device, unsigned char *data, size_t length);

// Read data from HID
// Implementing the io.Reader interface with this method.
func (dev *Device) Read(b []byte) (n int, err error) {
	// quick return when b is empty
	if len(b) == 0 {
		return 0, nil
	}

	// read data from hid device and handle error
	res := C.hid_read(dev.hidHandle, (*C.uchar)(&b[0]), C.size_t(len(b)))
	resInt := int(res)
	if resInt == -1 {
		return 0, dev.lastError()
	}

	// all done
	return resInt, nil
}

///** @brief Set the device handle to be non-blocking.
//
//	In non-blocking mode calls to hid_read() will return
//	immediately with a value of 0 if there is no data to be
//	read. In blocking mode, hid_read() will wait (block) until
//	there is data to read before returning.
//
//	Nonblocking can be turned on and off at any time.
//
//	@ingroup API
//	@param device A device handle returned from hid_open().
//	@param nonblock enable or not the nonblocking reads
//	 - 1 to enable nonblocking
//	 - 0 to disable nonblocking.
//
//	@returns
//		This function returns 0 on success and -1 on error.
//*/
//int  HID_API_EXPORT HID_API_CALL hid_set_nonblocking(hid_device *device, int nonblock);

// In non-blocking mode calls to hid_read() will return immediately with a value of 0 if there is no data to be read.
// In blocking mode, hid_read() will wait (block) until there is data to read before returning.
func (dev *Device) SetReadWriteNonBlocking(nonblocking bool) error {
	// convert blocking bool to nonblocking int
	nonblock := 0
	if nonblocking {
		nonblock = 1
	}

	// make the call and return error when call failed
	if C.hid_set_nonblocking(dev.hidHandle, C.int(nonblock)) != 0 {
		return dev.lastError()
	}

	// all done
	return nil
}

// /** @brief Send a Feature report to the device.
//
//  Feature reports are sent over the Control endpoint as a
//  Set_Report transfer.  The first byte of @p data[] must
//  contain the Report ID. For devices which only support a
//  single report, this must be set to 0x0. The remaining bytes
//  contain the report data. Since the Report ID is mandatory,
//  calls to hid_send_feature_report() will always contain one
//  more byte than the report contains. For example, if a hid
//  report is 16 bytes long, 17 bytes must be passed to
//  hid_send_feature_report(): the Report ID (or 0x0, for
//  devices which do not use numbered reports), followed by the
//  report data (16 bytes). In this example, the length passed
//  in would be 17.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param data The data to send, including the report number as
//  	the first byte.
//  @param length The length in bytes of the data to send, including
//  	the report number.
//
//  @returns
//  	This function returns the actual number of bytes written and
//  	-1 on error.
// */
// int HID_API_EXPORT HID_API_CALL hid_send_feature_report(hid_device *device, const unsigned char *data, size_t length);

// Send a feature report
func (dev *Device) SendFeatureReport(data []byte) (int, error) {
	res := C.hid_send_feature_report(dev.hidHandle, (*C.uchar)(&data[0]), C.size_t(len(data)))
	resInt := int(res)
	if resInt == -1 {
		return 0, dev.lastError()
	}
	return resInt, nil
}

// /** @brief Get a feature report from a HID device.
//
//  Make sure to set the first byte of @p data[] to the Report
//  ID of the report to be read.  Make sure to allow space for
//  this extra byte in @p data[].
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param data A buffer to put the read data into, including
//  	the Report ID. Set the first byte of @p data[] to the
//  	Report ID of the report to be read.
//  @param length The number of bytes to read, including an
//  	extra byte for the report ID. The buffer can be longer
//  	than the actual report.
//
//  @returns
//  	This function returns the number of bytes read and
//  	-1 on error.
// */
// int HID_API_EXPORT HID_API_CALL hid_get_feature_report(hid_device *device, unsigned char *data, size_t length);

// Get a FeatureReport from the HID device
func (dev *Device) GetFeatureReport(reportId byte, reportDataSize int) ([]byte, error) {
	reportSize := reportDataSize + 1
	buf := make([]byte, reportSize)
	buf[0] = reportId

	// send feature report
	res := C.hid_get_feature_report(dev.hidHandle, (*C.uchar)(&buf[0]), C.size_t(reportSize))
	resInt := int(res)
	if resInt == -1 {
		return nil, dev.lastError()
	}

	// all done
	return buf, nil
}

// /** @brief Close a HID device.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
// */
// void HID_API_EXPORT HID_API_CALL hid_close(hid_device *device);

// Close the device handle
func (dev *Device) Close() {
	C.hid_close(dev.hidHandle)
}

// /** @brief Get The Manufacturer String from a HID device.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param string A wide string buffer to put the data into.
//  @param maxlen The length of the buffer in multiples of wchar_t.
//
//  @returns
//  	This function returns 0 on success and -1 on error.
// */
// int HID_API_EXPORT_CALL hid_get_manufacturer_string(hid_device *device, wchar_t *string, size_t maxlen);

// Get manufacturer string from device
func (dev *Device) ManufacturerString() (string, error) {
	// create WcharString
	ws := wchar.NewWcharString(100)

	// retrieve manufacturer string from hid
	res := C.hid_get_manufacturer_string(dev.hidHandle, (*C.wchar_t)(unsafe.Pointer(ws.Pointer())), 100)
	if res != 0 {
		return "", dev.lastError()
	}

	// all done
	return ws.GoString()
}

// /** @brief Get The Product String from a HID device.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param string A wide string buffer to put the data into.
//  @param maxlen The length of the buffer in multiples of wchar_t.
//
//  @returns
//  	This function returns 0 on success and -1 on error.
// */
// int HID_API_EXPORT_CALL hid_get_product_string(hid_device *device, wchar_t *string, size_t maxlen);

// Get product string from device
func (dev *Device) ProductString() (string, error) {
	// create WcharString
	ws := wchar.NewWcharString(100)

	// retrieve manufacturer string from hid
	res := C.hid_get_product_string(dev.hidHandle, (*C.wchar_t)(unsafe.Pointer(ws.Pointer())), 100)
	if res != 0 {
		return "", dev.lastError()
	}

	// all done
	return ws.GoString()
}

// /** @brief Get The Serial Number String from a HID device.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param string A wide string buffer to put the data into.
//  @param maxlen The length of the buffer in multiples of wchar_t.
//
//  @returns
//  	This function returns 0 on success and -1 on error.
// */
// int HID_API_EXPORT_CALL hid_get_serial_number_string(hid_device *device, wchar_t *string, size_t maxlen);

// Get Serial number string from device
func (dev *Device) SerialNumberString() (string, error) {
	// create WcharString
	ws := wchar.NewWcharString(100)

	// retrieve manufacturer string from hid
	res := C.hid_get_serial_number_string(dev.hidHandle, (*C.wchar_t)(unsafe.Pointer(ws.Pointer())), 100)
	if res != 0 {
		return "", dev.lastError()
	}

	// all done
	return ws.GoString()
}

// /** @brief Get a string from a HID device, based on its string index.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//  @param string_index The index of the string to get.
//  @param string A wide string buffer to put the data into.
//  @param maxlen The length of the buffer in multiples of wchar_t.
//
//  @returns
//  	This function returns 0 on success and -1 on error.
// */
// int HID_API_EXPORT_CALL hid_get_indexed_string(hid_device *device, int string_index, wchar_t *string, size_t maxlen);

// Get a string by index. String length will be max 256 wchars.
func (dev *Device) GetIndexedString(index int) (string, error) {
	// create WcharString
	ws := wchar.NewWcharString(256)

	// retrieve manufacturer string from hid
	res := C.hid_get_indexed_string(dev.hidHandle, C.int(index), (*C.wchar_t)(unsafe.Pointer(ws.Pointer())), 256)
	if res != 0 {
		return "", dev.lastError()
	}

	// all done
	return ws.GoString()
}

// /** @brief Get a string describing the last error which occurred.
//
//  @ingroup API
//  @param device A device handle returned from hid_open().
//
//  @returns
//  	This function returns a string containing the last error
//  	which occurred or NULL if none has occurred.
// */
// HID_API_EXPORT const wchar_t* HID_API_CALL hid_error(hid_device *device);

func (dev *Device) lastError() error {
	return errors.New(dev.lastErrorString())
}

func (dev *Device) lastErrorString() string {
	wcharPtr := C.hid_error(dev.hidHandle)
	str, err := wchar.WcharStringPtrToGoString(unsafe.Pointer(wcharPtr))
	if err != nil {
		return fmt.Sprintf("Error retrieving error string: %s", err)
	}
	return str
}
