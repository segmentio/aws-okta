package sessioncache

import (
	"testing"

	"github.com/99designs/keyring"
)

func TestKrItemPerSessionStore(t *testing.T) {
	testStore(t, func() store {
		return &KrItemPerSessionStore{
			Keyring: keyring.NewArrayKeyring([]keyring.Item{}),
		}
	})
}
