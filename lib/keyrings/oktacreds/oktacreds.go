package oktacredskeyring

import (
	"encoding/json"
	"fmt"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib/v2/oktaclient"
	log "github.com/sirupsen/logrus"
)

// changing any of these will break keyring compatibility
const (
	keyringServiceName             = "aws-okta"
	keyringLibSecretCollectionName = "aws-okta"

	keyringFileDir = "~/.aws-okta/"

	// TODO: pretty sure this is metadata and we could do better if we broke compat
	keyringCredsLabel = "Okta credentials"
)

type Keyring struct {
	BackendType      string
	FilePasswordFunc func(prompt string) (string, error)

	keyring keyring.Keyring
}

// After Open, BackendType, FilePasswordFunc must not be changed.
func (k *Keyring) Open() error {
	// TODO(nick): not sure I understand this logic
	var allowedBackends []keyring.BackendType
	if k.BackendType != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(k.BackendType))
	}

	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		ServiceName:              keyringServiceName,
		LibSecretCollectionName:  keyringLibSecretCollectionName,
		FileDir:                  keyringFileDir,
		FilePasswordFunc:         k.FilePasswordFunc,
	})
	if err != nil {
		return err
	}
	k.keyring = kr
	return nil
}

// Put will Open if not open already
func (k *Keyring) Put(accountAlias string, creds oktaclient.Creds) error {
	log.Tracef("keyring %s putting creds: %v", accountAlias, creds)
	if k.keyring == nil {
		if err := k.Open(); err != nil {
			return fmt.Errorf("opening keyring: %w", err)
		}
	}
	encoded, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshalling creds: %w", err)
	}

	item := keyring.Item{
		Key:   accountAlias,
		Data:  encoded,
		Label: fmt.Sprintf("Okta credentials (%s)", accountAlias),
		// TODO: verify this is the correct setting
		KeychainNotTrustApplication: false,
	}

	log.Tracef("keyring %s put item: %v", accountAlias, item)
	return k.keyring.Set(item)
}

func (k *Keyring) Get(accountAlias string) (oktaclient.Creds, error) {
	log.Tracef("keyring %s getting creds", accountAlias)
	if k.keyring == nil {
		if err := k.Open(); err != nil {
			return oktaclient.Creds{}, fmt.Errorf("opening keyring: %w", err)
		}
	}

	item, err := k.keyring.Get(accountAlias)
	if err != nil {
		return oktaclient.Creds{}, fmt.Errorf("getting %s from keyring: %w", accountAlias, err)
	}

	var oktaCreds oktaclient.Creds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return oktaCreds, fmt.Errorf("unmarshalling okta creds: %w", err)
	}

	log.Tracef("keyring %s got creds %v", accountAlias, oktaCreds)
	return oktaCreds, nil
}
