package session

import (
	"testing"

	"github.com/99designs/keyring"
)

func TestSingleKrItemStore(t *testing.T) {
	testStore(t, func() store {
		return &SingleKrItemStore{
			Keyring: keyring.NewArrayKeyring([]keyring.Item{}),
		}
	})
}
