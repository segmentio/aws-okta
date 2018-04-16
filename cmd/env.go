package cmd

import (
	"github.com/spf13/cobra"
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Invokes `printenv`. Takes var names or prints all env",
	RunE:  runEnvCmd,
}

func init() {
	RootCmd.AddCommand(envCmd)
}

func runEnvCmd(cmd *cobra.Command, args []string) error {
	return runWithAwsEnv("printenv", args...)
}
