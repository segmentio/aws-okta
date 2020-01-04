package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib/v2/oktaclient"
)

// changing any of these will break keyring compatibility
const (
	keyringServiceName             = "aws-okta"
	keyringLibSecretCollectionName = "aws-okta"

	keyringFileDir = "~/.aws-okta/"

	// TODO: pretty sure this is metadata and we could do better if we broke compat
	keyringCredsLabel = "Okta credentials"
)

func keyringOpen(backendType string) (keyring.Keyring, error) {
	// TODO(nick): not sure I understand this logic
	var allowedBackends []keyring.BackendType
	if backendType != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backendType))
	}

	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		ServiceName:              keyringServiceName,
		LibSecretCollectionName:  keyringLibSecretCollectionName,
		FileDir:                  keyringFileDir,
		FilePasswordFunc: func(prompt string) (string, error) {
			return promptWithOutput(prompt, true, os.Stderr)
		},
	})
	return kr, err
}

func keyringCredsPut(accountAlias string, creds oktaclient.Creds) error {
	kr, err := keyringOpen(FlagKeyringBackend)
	if err != nil {
		return fmt.Errorf("opening keyring: %w", err)
	}
	k := accountAlias

	encoded, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshalling creds: %w", err)
	}

	item := keyring.Item{
		Key:   k,
		Data:  encoded,
		Label: fmt.Sprintf("Okta credentials (%s)", accountAlias),
		// TODO: verify this is the correct setting
		KeychainNotTrustApplication: false,
	}

	return kr.Set(item)
}

func keyringCredsGet(accountAlias string) (oktaclient.Creds, error) {
	kr, err := keyringOpen(FlagKeyringBackend)
	if err != nil {
		return oktaclient.Creds{}, fmt.Errorf("opening keyring: %w", err)
	}
	k := accountAlias

	item, err := kr.Get(k)
	if err != nil {
		return oktaclient.Creds{}, err
	}

	var oktaCreds oktaclient.Creds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return oktaCreds, fmt.Errorf("unmarshalling okta creds: %w", err)
	}

	return oktaCreds, nil
}
