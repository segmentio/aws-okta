package cmd

import (
	"os"

	"github.com/99designs/keyring"
)

// changing any of these will break keyring compatibility
const (
	// this keychain name is for backwards compatibility
	keyringServiceName             = "aws-okta-login"
	keyringLibSecretCollectionName = "awsvault"
	keyringFileDir                 = "~/.aws-okta/"
)

func keyringPrompt(prompt string) (string, error) {
	return promptWithOutput(prompt, true, os.Stderr)
}

func openKeyring(b string) (keyring.Keyring, error) {
	var allowedBackends []keyring.BackendType
	if b != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(b))
	}

	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		ServiceName:              keyringServiceName,
		LibSecretCollectionName:  keyringLibSecretCollectionName,
		FileDir:                  keyringFileDir,
		FilePasswordFunc:         keyringPrompt,
	})
	return kr, err
}
