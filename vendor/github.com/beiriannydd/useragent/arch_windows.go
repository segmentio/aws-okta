package useragent

import (
	"runtime"
)

func currentArchitecture() string {
	// overrides for arch output
	var convert = map[string]string{
		"amd64":    "; Win64; x64",
		"amd64p32": "; Win64; x64",
		"386":      "",
		"arm64":    "; Win64; arm64",
	}
	// defaults (better than nothing)
	os := "Windows"
	arch := runtime.GOARCH
	// ver outputs the OS Version
	out, _ := run("cmd", "ver")
	// There's a second line which is a copyright message.
	if len(out) >= 1 {
		// moved parsing the version out to shared code to simplify testing
		os = parseWindowsVersion(out[0])
	}
	if replace, found := convert[arch]; found {
		// overrides for arch.
		arch = replace
	}
	return os + arch
}
