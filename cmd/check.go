package cmd

import (
	"fmt"

	"github.com/mulesoft-labs/aws-keycloak/provider"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check will authenticate you through keycloak and store session.",
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

	_, awsshortrole, err := p.Retrieve(awsrole)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully connected to AWS with role %s.", awsshortrole)

	return nil
}
