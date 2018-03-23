package main

import "github.com/segmentio/aws-okta/cmd"

var (
	// This is updated via linker flags
	Version = "dev"
)

func main() {
	cmd.Execute(Version)
}
