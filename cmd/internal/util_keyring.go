package cmd

import (
	"os"

	oktacredskeyring "github.com/segmentio/aws-okta/lib/v2/keyrings/oktacreds"
	"github.com/segmentio/aws-okta/lib/v2/oktaclient"
)

func filePasswordFunc(prompt string) (string, error) {
	return promptWithOutput(prompt, true, os.Stderr)
}

func keyringCredsPut(accountAlias string, creds oktaclient.Creds) error {
	kr := oktacredskeyring.Keyring{
		BackendType:      FlagKeyringBackend,
		FilePasswordFunc: filePasswordFunc,
	}
	return kr.Put(accountAlias, creds)
}

func keyringCredsGet(accountAlias string) (oktaclient.Creds, error) {
	kr := oktacredskeyring.Keyring{
		BackendType:      FlagKeyringBackend,
		FilePasswordFunc: filePasswordFunc,
	}
	return kr.Get(accountAlias)
}
