package wchar

/*
#cgo darwin LDFLAGS: -liconv
#cgo windows LDFLAGS: -liconv
#include <stdlib.h>
#ifdef __APPLE__
#  define LIBICONV_PLUG 1
#endif
#include <iconv.h>
#include <wchar.h>
#include <string.h>

void putWcharAt(char *buffer, void *wchar, int at) {
	memcpy(buffer+at, wchar, 4);
}
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// iconv charset strings
var (
	iconvCharsetWchar = C.CString("wchar_t//TRANSLIT")
	iconvCharsetChar  = C.CString("//TRANSLIT")
	iconvCharsetAscii = C.CString("ascii//TRANSLIT")
	iconvCharsetUtf8  = C.CString("utf-8//TRANSLIT")
)

// iconv documentation:
// Use iconv. It seems to support conversion between char and wchar_t
// http://www.gnu.org/savannah-checkouts/gnu/libiconv/documentation/libiconv-1.13/iconv_open.3.html
// http://www.gnu.org/savannah-checkouts/gnu/libiconv/documentation/libiconv-1.13/iconv.3.html
// http://www.gnu.org/savannah-checkouts/gnu/libiconv/documentation/libiconv-1.13/iconv_close.3.html

// Internal helper function, wrapped by several other functions
func convertGoStringToWcharString(input string) (output WcharString, err error) {
	// quick return when input is an empty string
	if input == "" {
		return NewWcharString(0), nil
	}

	// open iconv
	iconv, errno := C.iconv_open(iconvCharsetWchar, iconvCharsetUtf8)
	if iconv == nil || errno != nil {
		return nil, fmt.Errorf("Could not open iconv instance: %s", errno)
	}
	defer C.iconv_close(iconv)

	// calculate bufferSizes in bytes for C
	bytesLeftInCSize := C.size_t(len([]byte(input))) // count exact amount of bytes from input
	bytesLeftOutCSize := C.size_t(len(input) * 4)    // wide char seems to be 4 bytes for every single- or multi-byte character. Not very sure though.

	// input for C. makes a copy using C malloc and therefore should be free'd.
	inputCString := C.CString(input)
	defer C.free(unsafe.Pointer(inputCString))

	// output for C
	outputCString := (*C.char)(C.malloc(bytesLeftOutCSize))
	defer C.free(unsafe.Pointer(outputCString))

	// call iconv for conversion of charsets, return on error
	saveInputCString, saveOutputCString := inputCString, outputCString
	_, errno = C.iconv(iconv, &inputCString, &bytesLeftInCSize, &outputCString, &bytesLeftOutCSize)
	if errno != nil {
		return nil, errno
	}
	inputCString, outputCString = saveInputCString, saveOutputCString

	outputLen := len(input)*4 - int(bytesLeftOutCSize)
	outputChars := make([]int8, outputLen)
	C.memcpy(unsafe.Pointer(&outputChars[0]), unsafe.Pointer(outputCString), C.size_t(outputLen))

	// convert []int8 to WcharString
	// create WcharString with same length as input, and one extra position for the null terminator.
	output = make(WcharString, 0, len(input)+1)
	// create buff to convert each outputChar
	wcharAsByteAry := make([]byte, 4)
	// loop for as long as there are output chars
	for len(outputChars) >= 4 {
		// create 4 position byte slice
		wcharAsByteAry[0] = byte(outputChars[0])
		wcharAsByteAry[1] = byte(outputChars[1])
		wcharAsByteAry[2] = byte(outputChars[2])
		wcharAsByteAry[3] = byte(outputChars[3])
		// combine 4 position byte slice into uint32
		wcharAsUint32 := binary.LittleEndian.Uint32(wcharAsByteAry)
		// find null terminator (doing this right?)
		if wcharAsUint32 == 0x0 {
			break
		}
		// append uint32 to outputUint32
		output = append(output, Wchar(wcharAsUint32))
		// reslice the outputChars
		outputChars = outputChars[4:]
	}
	// Add null terminator
	output = append(output, Wchar(0x0))

	return output, nil
}

// Internal helper function, wrapped by several other functions
func convertWcharStringToGoString(ws WcharString) (output string, err error) {
	// return empty string if len(input) == 0
	if len(ws) == 0 {
		return "", nil
	}

	// open iconv
	iconv, errno := C.iconv_open(iconvCharsetUtf8, iconvCharsetWchar)
	if iconv == nil || errno != nil {
		return "", fmt.Errorf("Could not open iconv instance: %s", errno.Error())
	}
	defer C.iconv_close(iconv)

	inputCLength := C.size_t(len(ws) * 4)
	inputAsCChars := (*C.char)(C.malloc(inputCLength))
	C.memset(unsafe.Pointer(inputAsCChars), C.int(0), inputCLength)
	defer C.free(unsafe.Pointer(inputAsCChars))
	for i, nextWchar := range ws {
		// find null terminator
		if nextWchar == 0 {
			break
		}

		C.putWcharAt(inputAsCChars, unsafe.Pointer(&nextWchar), C.int(i*4))
	}

	// calculate buffer size for input
	bytesLeftInCSize := inputCLength

	// calculate buffer size for output
	bytesLeftOutCSize := inputCLength

	// create output buffer
	outputChars := (*C.char)(C.malloc(bytesLeftOutCSize))
	defer C.free(unsafe.Pointer(outputChars))

	// call iconv for conversion of charsets, return on error
	saveInputAsCChars, saveOutputChars := inputAsCChars, outputChars
	_, errno = C.iconv(iconv, &inputAsCChars, &bytesLeftInCSize, &outputChars, &bytesLeftOutCSize)
	if errno != nil {
		return "", errno
	}
	inputAsCChars, outputChars = saveInputAsCChars, saveOutputChars

	// conver output buffer to go string
	output = C.GoString(outputChars)

	return output, nil
}

// Internal helper function, wrapped by other functions
func convertGoRuneToWchar(r rune) (output Wchar, err error) {
	// quick return when input is an empty string
	if r == '\000' {
		return Wchar(0), nil
	}

	// open iconv
	iconv, errno := C.iconv_open(iconvCharsetWchar, iconvCharsetUtf8)
	if iconv == nil || errno != nil {
		return Wchar(0), fmt.Errorf("Could not open iconv instance: %s", errno)
	}
	defer C.iconv_close(iconv)

	// bufferSizes for C
	bytesLeftInCSize := C.size_t(4)
	bytesLeftOutCSize := C.size_t(4 * 4)
	// TODO/FIXME: the last 4 bytes as indicated by bytesLeftOutCSize wont be used...
	// iconv assumes each given char to be one wchar.
	// in this case we know that the given 4 chars will actually be one unicode-point and therefore will result in one wchar.
	// hence, we give the iconv library a buffer of 4 char's size, and tell the library that it has a buffer of 32 char's size.
	// if the rune would actually contain 2 unicode-point's this will result in massive failure (and probably the end of a process' life)

	// input for C. makes a copy using C malloc and therefore should be free'd.
	runeCString := C.CString(string(r))
	defer C.free(unsafe.Pointer(runeCString))

	// create output buffer
	outputChars := (*C.char)(C.malloc(4))
	defer C.free(unsafe.Pointer(outputChars))

	// call iconv for conversion of charsets
	saveRuneCString, saveOutputChars := runeCString, outputChars
	_, errno = C.iconv(iconv, &runeCString, &bytesLeftInCSize, &outputChars, &bytesLeftOutCSize)
	if errno != nil {
		return '\000', errno
	}
	runeCString, outputChars = saveRuneCString, saveOutputChars

	// convert C.char's to Wchar
	wcharAsByteAry := make([]byte, 4)
	C.memcpy(unsafe.Pointer(&wcharAsByteAry[0]), unsafe.Pointer(outputChars), 4)

	// combine 4 position byte slice into uint32 and convert to Wchar.
	wcharAsUint32 := binary.LittleEndian.Uint32(wcharAsByteAry)
	output = Wchar(wcharAsUint32)

	return output, nil
}

// Internal helper function, wrapped by several other functions
func convertWcharToGoRune(w Wchar) (output rune, err error) {
	// return  if len(input) == 0
	if w == 0 {
		return '\000', nil
	}

	// open iconv
	iconv, errno := C.iconv_open(iconvCharsetUtf8, iconvCharsetWchar)
	if iconv == nil || errno != nil {
		return '\000', fmt.Errorf("Could not open iconv instance: %s", errno.Error())
	}
	defer C.iconv_close(iconv)

	// split Wchar into bytes
	wcharAsBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(wcharAsBytes, uint32(w))

	// place the wcharAsBytes into wcharAsCChars
	wcharAsCChars := (*C.char)(C.malloc(4))
	defer C.free(unsafe.Pointer(wcharAsCChars))
	C.memcpy(unsafe.Pointer(wcharAsCChars), unsafe.Pointer(&wcharAsBytes[0]), 4)

	// calculate buffer size for input
	bytesLeftInCSize := C.size_t(4)

	// calculate buffer size for output
	bytesLeftOutCSize := C.size_t(4)

	// create output buffer
	outputChars := (*C.char)(C.malloc(bytesLeftOutCSize))
	defer C.free(unsafe.Pointer(outputChars))

	// call iconv for conversion of charsets
	saveWcharAsCChars, saveOutputChars := wcharAsCChars, outputChars
	_, errno = C.iconv(iconv, &wcharAsCChars, &bytesLeftInCSize, &outputChars, &bytesLeftOutCSize)
	if errno != nil {
		return '\000', errno
	}
	wcharAsCChars, outputChars = saveWcharAsCChars, saveOutputChars

	// convert outputChars ([]int8, len 4) to Wchar
	// TODO: can this conversion be done easier by using this: ?
	// output = *((*rune)(unsafe.Pointer(&outputChars[0])))
	runeAsByteAry := make([]byte, 4)
	C.memcpy(unsafe.Pointer(&runeAsByteAry[0]), unsafe.Pointer(outputChars), 4)

	// combine 4 position byte slice into uint32 and convert to rune.
	runeAsUint32 := binary.LittleEndian.Uint32(runeAsByteAry)
	output = rune(runeAsUint32)

	return output, nil
}
