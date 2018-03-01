package cmd

import (
	"encoding/json"
	"fmt"

	log "github.com/Sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add your okta credentials",
	RunE:  add,
}

func init() {
	RootCmd.AddCommand(addCmd)
}

func add(cmd *cobra.Command, args []string) error {
	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		// this keychain name is for backwards compatibility
		ServiceName:             "aws-okta",
		LibSecretCollectionName: "awsvault",
	})

	if err != nil {
		log.Fatal(err)
	}

	// Ask username password from prompt
	organization, err := lib.Prompt("Okta organization", false)
	if err != nil {
		return err
	}

	username, err := lib.Prompt("Okta username", false)
	if err != nil {
		return err
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
	}

	encoded, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	item := keyring.Item{
		Key:   "okta-creds",
		Data:  encoded,
		Label: "okta credentials",
		KeychainNotTrustApplication: false,
	}

	if err := kr.Set(item); err != nil {
		return ErrFailedToSetCredentials
	}

	log.Infof("Added credentials for user %s", username)
	return nil
}
