package cmd

import (
	"github.com/spf13/cobra"
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Invoke aws subcommands (always use -- before subcommand and flags)",
	RunE:  runAwsCmd,
}

func init() {
	RootCmd.AddCommand(awsCmd)
}

func runAwsCmd(cmd *cobra.Command, args []string) error {
	return runWithAwsEnv("aws", args...)
}
