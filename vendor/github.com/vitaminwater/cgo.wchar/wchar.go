package wchar

import (
	"unsafe"
)

// return pointer to this Wchar
func (w Wchar) Pointer() *Wchar {
	return &w
}

// convert Wchar to Go rune
// will return an error when conversion failed.
func (w Wchar) GoRune() (rune, error) {
	r, err := convertWcharToGoRune(w)
	if err != nil {
		return '\000', err
	}
	return r, nil
}

func FromGoRune(r rune) (Wchar, error) {
	return convertGoRuneToWchar(r)
}

// FromWcharPtr converts a *C.wchar_t to a Go Wchar
func FromWcharPtr(ptr unsafe.Pointer) Wchar {
	// quick return for null pointer
	if uintptr(ptr) == 0x0 {
		return Wchar(0)
	}

	return *((*Wchar)(ptr))
}

// go representation of a wchar string (array)
type WcharString []Wchar

// NewWcharString creates a new WcharString with given length.
// This is required when the WcharString is being used as write buffer for a call to a C function.
func NewWcharString(length int) WcharString {
	return make(WcharString, length)
}

// FromGoString creates a WcharString from a Go string
func FromGoString(s string) (WcharString, error) {
	return convertGoStringToWcharString(s)
}

// FromWcharStringPtr creates a WcharString from a *C.wchar_t.
// It finds the end of the *C.wchar_t string by finding the null terminator.
func FromWcharStringPtr(first unsafe.Pointer) WcharString {
	// quick return for null pointer
	if uintptr(first) == 0x0 {
		return NewWcharString(0)
	}

	// Get uintptr from first wchar_t
	wcharPtr := uintptr(first)

	// allocate new WcharString to fill with data. Cap is unknown
	ws := make(WcharString, 0)

	// append data using pointer arithmic
	var w Wchar
	for {
		// get Wchar value
		w = *((*Wchar)(unsafe.Pointer(wcharPtr)))

		// check for null byte terminator
		if w == 0 {
			break
		}

		// append Wchar to WcharString
		ws = append(ws, w)

		// increment pointer 4 bytes
		wcharPtr += 4
	}

	// all done
	return ws
}

// convert a *C.wchar_t and length int to a WcharString
func FromWcharStringPtrN(first unsafe.Pointer, length int) WcharString {
	if uintptr(first) == 0x0 {
		return NewWcharString(0)
	}

	// Get uintptr from first wchar_t
	wcharPtr := uintptr(first)

	// allocate new WcharString to fill with data. Only set cap, later use append
	ws := make(WcharString, 0, length)

	// append data using pointer arithmic
	var x Wchar
	for i := 0; i < length; i++ {
		// get Wchar
		x = *((*Wchar)(unsafe.Pointer(wcharPtr)))

		// check for null byte terminator
		if x == 0 {
			break
		}

		// append Wchar to WcharString
		ws = append(ws, x)

		// increment pointer 4 bytes
		wcharPtr += 4
	}

	// all done
	return ws
}

// return pointer to first element
func (ws WcharString) Pointer() *Wchar {
	return &ws[0]
}

// convert WcharString to Go string
// will return an error when conversion failed.
func (ws WcharString) GoString() (string, error) {
	str, err := convertWcharStringToGoString(ws)
	if err != nil {
		return "", err
	}
	return str, nil
}

// convert a null terminated *C.wchar_t to a Go string
// convenient wrapper for WcharPtrToWcharString(first).GoString()
func WcharStringPtrToGoString(first unsafe.Pointer) (string, error) {
	if uintptr(first) == 0x0 {
		return "", nil
	}
	return convertWcharStringToGoString(FromWcharStringPtr(first))
}

// convert a *C.wchar_t and length int to a Go string
// convenient wrapper for WcharPtrIntToWcharString(first, length).GoString()
func WcharStringPtrNToGoString(first unsafe.Pointer, length int) (string, error) {
	if uintptr(first) == 0x0 {
		return "", nil
	}
	return convertWcharStringToGoString(FromWcharStringPtrN(first, length))
}

// convenient wrapper for WcharPtrToWcharString(first).GoString()
func WcharPtrToGoRune(first unsafe.Pointer) (rune, error) {
	if uintptr(first) == 0x0 {
		return '\000', nil
	}
	return convertWcharToGoRune(FromWcharPtr(first))
}
