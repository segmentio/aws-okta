package useragent

import (
	"runtime"
	"strings"
)

func currentArchitecture() string {
	var convert = map[string]string{
		"amd64":    "Intel",
		"amd64p32": "Intel",
		"386":      "Intel",
		"ppc":      "PPC",
		"ppc64":    "PPC",
		"ppc64le":  "PPC",
		"arm":      "Mobile",
		"arm64":    "Mobile",
	}
	// defaults (better than nothing)
	os := "darwin"
	arch := runtime.GOARCH
	// sw_vers shows the OS name and version for Mac OS X.
	out, _ := run("sw_vers")
	if len(out) >= 2 {
		parsed := map[string]string{}
		for _, line := range out {
			// results are Key: Value
			fields := strings.SplitN(line, ":", 2)
			key := strings.TrimSpace(fields[0])
			val := strings.TrimSpace(fields[1])
			parsed[key] = val
		}
		if val, found := parsed["ProductName"]; found {
			os = val
		}
		if val, found := parsed["ProductVersion"]; found {
			os = os + " " + val
		}

	}
	if replace, found := convert[arch]; found {
		// overrides for arch.
		arch = replace
	}
	return "Macintosh; " + arch + " " + os
}
