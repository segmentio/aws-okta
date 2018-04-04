package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	version = "1.0.0"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version information and exit",
	Run:   versionRun,
}

func init() {
	RootCmd.AddCommand(versionCmd)
}

func versionRun(cmd *cobra.Command, args []string) {
	fmt.Println(version)
}
