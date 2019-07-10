## cgo.wchar

Helps with using wchars with cgo.

### Example
Example from the go.hid library:
```go
func (dev *Device) ManufacturerString() (string, error) {
	// create WcharString
	ws := wchar.NewWcharString(100)

	// retrieve manufacturer string from hid
	res := C.hid_get_manufacturer_string(dev.hidHandle, (*C.wchar_t)(ws.Pointer()), 100)
	if res != 0 {
		return "", dev.lastError()
	}

	// get WcharString as Go string
	str := ws.GoString()

	// all done
	return str, nil
}
```
