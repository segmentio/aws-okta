package cmd

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

var (
	organization string
	oktaRegion   string
	oktaDomain   string
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add your okta credentials",
	RunE:  add,
}

func init() {
	RootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVarP(&organization, "organization", "o", "", "Okta organization")
	addCmd.Flags().StringVarP(&oktaRegion, "region", "r", "", "Okta region")
	addCmd.Flags().StringVarP(&oktaDomain, "domain", "a", "", "Okta domain address")
	addCmd.Flags().StringVarP(&username, "username", "u", "", "Okta username")
}

func add(cmd *cobra.Command, args []string) error {
	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	kr, err := lib.OpenKeyring(allowedBackends)

	if err != nil {
		log.Fatal(err)
	}

	if _, err := kr.Get("okta-creds"); err == nil {
		log.Infof("Credentials already added.")
		return nil
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("command", "add"),
		})
	}

	// Ask username password from prompt
	if organization == "" {
		organization, err = lib.Prompt("Okta organization", false)
		if err != nil {
			return err
		}

	}

	if oktaRegion == "" {
		oktaRegion, err = lib.Prompt("Okta region ([us], emea, preview)", false)
		if err != nil {
			return err
		}
		if oktaRegion == "" {
			oktaRegion = "us"
		}

	}

	if oktaDomain == "" {
		oktaDomain, err = lib.Prompt("Okta domain ["+oktaRegion+".okta.com]", false)
		if err != nil {
			return err
		}
	}

	if username == "" {
		username, err = lib.Prompt("Okta username", false)
		if err != nil {
			return err
		}
	}

	password, err := lib.Prompt("Okta password", true)
	if err != nil {
		return err
	}
	fmt.Println()

	creds := lib.OktaCreds{
		Organization: organization,
		Username:     username,
		Password:     password,
		Domain:       oktaDomain,
	}

	// Profiles aren't parsed during `add`, but still want
	// to centralize the MFA config logic
	var dummyProfiles lib.Profiles
	updateMfaConfig(cmd, dummyProfiles, "", &mfaConfig)

	if err := creds.Validate(mfaConfig); err != nil {
		log.Debugf("Failed to validate credentials: %s", err)
		return ErrFailedToValidateCredentials
	}

	encoded, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	item := keyring.Item{
		Key:                         "okta-creds",
		Data:                        encoded,
		Label:                       "okta credentials",
		KeychainNotTrustApplication: false,
	}

	if err := kr.Set(item); err != nil {
		log.Debugf("Failed to add user to keyring: %s", err)
		return ErrFailedToSetCredentials
	}

	log.Infof("Added credentials for user %s", username)
	return nil
}
