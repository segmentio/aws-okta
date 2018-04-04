package cmd

import (
	"github.com/mulesoft-labs/aws-keycloak/provider"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "check will authenticate you through keycloak and store session.",
	RunE:  checkRun,
}

func init() {
	RootCmd.AddCommand(checkCmd)
}

func checkRun(cmd *cobra.Command, args []string) error {
	k, err := provider.NewKeycloakProvider(kr, kcprofile, section)
	if err != nil {
		return err
	}
	a := &provider.AwsProvider{
		Keyring: kr,
	}
	p := provider.Provider{
		A: a,
		K: k,
	}

	_, _, err = p.Retrieve(awsrole)
	if err != nil {
		return err
	}

	return nil
}
