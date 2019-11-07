package session

import "github.com/99designs/keyring"

func New(kr keyring.Keyring) *KeyringSessionCache {
	return &KeyringSessionCache{keyring: kr}
}

type KeyringSessionCache struct {
	keyring keyring.Keyring
}

func (s *KeyringSessionCache) Get(key string) ([]byte, error) {
	keyringItem, err := s.keyring.Get(key)
	if err != nil {
		return []byte{}, err
	}

	return keyringItem.Data, nil
}

func (s *KeyringSessionCache) Put(key string, data []byte, label string) error {
	newCookieItem := keyring.Item{
		Key:                         key,
		Data:                        data,
		Label:                       label,
		KeychainNotTrustApplication: false,
	}
	return s.keyring.Set(newCookieItem)
}
