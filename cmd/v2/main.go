package main

import cmd "github.com/segmentio/aws-okta/cmd/v2/internal"

// These are set via linker flags
var (
	Version           = "dev"
	AnalyticsWriteKey = ""
)

func main() {
	// vars set by linker flags must be strings...
	cmd.Execute(Version, AnalyticsWriteKey)
}
