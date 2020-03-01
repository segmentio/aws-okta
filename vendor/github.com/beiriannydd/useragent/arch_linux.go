package useragent

import (
	"runtime"
	"strings"
)

func currentArchitecture() string {
	var convert = map[string]string{
		"amd64": "x86_64",
	}
	// defaults (better than nothing)
	os := "Linux"
	arch := runtime.GOARCH
	// uname -a gives everything we need
	out, _ := run("uname", "-a")
	if len(out) == 1 {
		// split into fields by whitespace
		fields := strings.Fields(out[0])
		os = fields[0]
		arch = fields[11]
	}
	if replace, found := convert[arch]; found {
		// overrides for arch.
		arch = replace
	}
	return os + " " + arch
}
