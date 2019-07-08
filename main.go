package main

import (
	"runtime/debug"

	"github.com/segmentio/aws-okta/cmd"
)

var (
	AnalyticsWriteKey = ""
)

// overrideable by linker flags, but if not overridden, will be looked up from
// module build info
var Version = ""

func init() {
	if Version != "" {
		return
	}

	if buildinfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildinfo.Main.Version
	}
}

func main() {
	// vars set by linker flags must be strings...
	cmd.Execute(Version, AnalyticsWriteKey)
}
