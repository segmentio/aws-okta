package sessioncache

import (
	"encoding/json"
	"time"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"

	// use xerrors until 1.13 is stable/oldest supported version
	"golang.org/x/xerrors"
)

// KrItemPerSessionStore stores one session in one keyring item
//
// This is the classic session store implementation. Its main drawback is that on macOS,
// without code signing, you need to reauthorize the binary between upgrades *for each
// item*.
type KrItemPerSessionStore struct {
	Keyring keyring.Keyring
}

// Get returns the session from the keyring at k.Key()
//
// If the keyring item is not found, returns wrapped keyring.ErrKeyNotFound
//
// If the session is found, but is expired, returns wrapped ErrSessionExpired
func (s *KrItemPerSessionStore) Get(k Key) (*Session, error) {
	keyStr := k.Key()
	item, err := s.Keyring.Get(keyStr)
	if err != nil {
		log.Debugf("cache get `%s`: miss (read error): %s", keyStr, err)
		return nil, xerrors.Errorf("failed Keyring.Get(%q): %w", keyStr, err)
	}

	var session Session

	if err = json.Unmarshal(item.Data, &session); err != nil {
		log.Debugf("cache get `%s`: miss (unmarshal error): %s", keyStr, err)
		return nil, xerrors.Errorf("failed unmarshal for %q: %w", keyStr, err)
	}

	if session.Expiration.Before(time.Now()) {
		log.Debugf("cache get `%s`: expired", keyStr)
		return nil, xerrors.Errorf("%q expired at %s: %w", keyStr, session.Expiration, ErrSessionExpired)
	}

	log.Debugf("cache get `%s`: hit", keyStr)
	return &session, nil
}

func (s *KrItemPerSessionStore) Put(k Key, session *Session) error {
	keyStr := k.Key()
	bytes, err := session.Bytes()
	if err != nil {
		log.Debugf("cache put `%s`: error (marshal): %s", keyStr, err)
		return err
	}

	log.Debugf("Writing session for %s to keyring", session.Name)
	item := keyring.Item{
		Key:                         k.Key(),
		Label:                       "aws session for " + session.Name,
		Data:                        bytes,
		KeychainNotTrustApplication: false,
	}
	if err := s.Keyring.Set(item); err != nil {
		log.Debugf("cache put `%s`: error (write): %s", keyStr, err)
		return err
	}

	return nil
}
