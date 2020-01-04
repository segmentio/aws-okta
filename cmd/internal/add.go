package cmd

import (
	"fmt"
	"os"

	"github.com/segmentio/aws-okta/lib/v2/oktaclient"
	"github.com/spf13/cobra"
)

var (
	FlagOktaUsername     string
	FlagOktaDomain       string
	FlagOktaAccountAlias string
	FlagCredsNoValidate  bool
)

func init() {
	var addCmd = &cobra.Command{
		Use:   "add <username> <domain>",
		Short: "add your okta credentials",
		RunE:  add,
	}
	RootCmd.AddCommand(addCmd)
	// TODO: does this even need to be configurable?
	addCmd.Flags().StringVarP(&FlagOktaAccountAlias, "account-alias", "", "", "Okta account alias (default `default`)")
	addCmd.Flags().BoolVarP(&FlagCredsNoValidate, "no-validate", "", false, "Disable credentials validation with Okta")
}

const AnalyticsCommandNameAdd = "add"

func add(cmd *cobra.Command, args []string) error {
	Analytics.TrackRanCommand(AnalyticsCommandNameAdd)

	if len(args) != 2 {
		return &ErrBadArgCount{
			Actual:   len(args),
			Expected: 2,
		}
	}
	username := args[0]
	domain := args[1]

	accountAlias := FlagOktaAccountAlias
	if accountAlias == "" {
		// TODO const
		accountAlias = "default"
	}

	password, err := prompt("Okta password", true)
	if err != nil {
		// TODO: does cobra deal with wrapped errors well?
		return fmt.Errorf("Failed to prompt for password: %w", err)
	}

	/* TODO
	// Profiles aren't parsed during `add`, but still want
	// to centralize the MFA config logic
	var dummyProfiles profiles.Profiles
	updateMfaConfig(cmd, dummyProfiles, "", &mfaConfig)
	creds.MFA = mfaConfig
	*/
	creds := oktaclient.Creds{
		Username: username,
		Password: password,
		Domain:   domain,
	}

	oktaCl := oktaclient.Client{
		Creds: creds,
	}

	if !FlagCredsNoValidate {
		fmt.Fprintf(os.Stderr, "Validating credentials...\n")
		if err := oktaCl.AuthenticateCreds(); err != nil {
			return fmt.Errorf("Failed to validate credentials: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Credentials validated!\n")
	}

	if err := keyringCredsPut(accountAlias, creds); err != nil {
		return fmt.Errorf("Failed to save credentials: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Saved credentials to keyring for user %s@%s (%s)\n", username, domain, accountAlias)
	return nil
}
