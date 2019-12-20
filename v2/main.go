package main

import cmd "github.com/segmentio/aws-okta/v2/cmd"

// These are set via linker flags
var (
	Version           = "dev"
	AnalyticsWriteKey = ""
)

func main() {
	cmd.Execute(Version, AnalyticsWriteKey)
}
