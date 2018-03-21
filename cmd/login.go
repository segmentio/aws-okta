package cmd

import (
	"github.com/mulesoft-labs/aws-keycloak/lib"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login will authenticate you through keycloak and store session (a way to test that your credentials work).",
	RunE:  loginRun,
}

func init() {
	RootCmd.AddCommand(loginCmd)
}

func loginRun(cmd *cobra.Command, args []string) error {

	p, err := lib.NewKeycloakProvider(kr, kcprofile, section)
	if err != nil {
		return err
	}
	a := &lib.AwsProvider{
		Keyring: kr,
	}
	c := lib.Provider{
		A: a,
		P: p,
	}

	_, _, err = c.Retrieve(awsrole)
	if err != nil {
		return err
	}

	return nil
}
