package cmd

import (
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check will authenticate you through keycloak and store session.",
	RunE:  runCheck,
}

func init() {
	RootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return ErrTooManyArguments
	}
	return runWithAwsEnv("aws", "sts", "get-caller-identity")
}
