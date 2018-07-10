package cmd

import (
	"github.com/spf13/cobra"
)

var envCmd = &cobra.Command{
	Use:     "env",
	Short:   "Invokes `printenv`. Takes var names or prints AWS env.",
	Example: "  aws-keycloak -p power-devx env\n  export AWS_ACCESS_KEY_ID=$(aws-keycloak -p power-devx env AWS_ACCESS_KEY_ID)\n  export `aws-keycloak -p power-devx env`",
	RunE:    runEnvCmd,
}

func init() {
	RootCmd.AddCommand(envCmd)
}

func runEnvCmd(cmd *cobra.Command, args []string) error {
	return runWithAwsEnv(false, "printenv", args...)
}
