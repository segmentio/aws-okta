package sessioncache

import (
	"encoding/json"
	"time"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"

	// use xerrors until 1.13 is stable/oldest supported version
	"golang.org/x/xerrors"
)

// TODO: make this configurable
const KeyringItemKey = "session-cache"
const KeyringItemLabel = "aws-okta session cache"

type singleKrItemDb struct {
	Sessions map[string]Session
}

// SingleKrItemStore stores all sessions in a single keyring item
//
// This is mostly for MacOS keychain, where because we don't sign aws-okta properly, the
// user needs to reauth the aws-okta binary for every item on every upgrade. By collapsing
// all sessions into a single item, we only need to reauth once per upgrade/build
type SingleKrItemStore struct {
	Keyring keyring.Keyring
}

// getDb gets our item from the keyring and unmarshals it
//
// if the keyring item is not found, returns wrapped keyring.ErrKeyNotFound
func (s *SingleKrItemStore) getDb() (*singleKrItemDb, error) {
	item, err := s.Keyring.Get(KeyringItemKey)

	if err != nil {
		return nil, xerrors.Errorf("failed Keyring.Get(%q): %w", KeyringItemKey, err)
	}

	var unmarshalled singleKrItemDb
	if err := json.Unmarshal(item.Data, &unmarshalled); err != nil {
		return nil, xerrors.Errorf("failed unmarshal for %q: %w", KeyringItemKey, err)
	}

	return &unmarshalled, nil
}

// Get loads the db from the keyring, and returns the session at k.Key()
//
// If the keyring item is not found (the db hasn't been written) or the key is
// not found, returns wrapped keyring.ErrKeyNotFound
//
// If the session is found, but is expired, returns wrapped ErrSessionExpired
func (s *SingleKrItemStore) Get(k Key) (*Session, error) {
	keyStr := k.Key()

	currentDb, err := s.getDb()
	if err != nil {
		log.Debugf("cache get `%s`: miss (read error): %s", keyStr, err)
		return nil, xerrors.Errorf("failed loading db for %q: %w", keyStr, err)
	}

	session, ok := currentDb.Sessions[keyStr]
	if !ok {
		log.Debugf("cache get `%s`: miss", keyStr)
		return nil, xerrors.Errorf("failed finding session for %q: %w", keyStr, keyring.ErrKeyNotFound)
	}

	if session.Expiration.Before(time.Now()) {
		log.Debugf("cache get `%s`: expired", keyStr)
		return nil, xerrors.Errorf("session expired for %q: %w", keyStr, ErrSessionExpired)
	}

	log.Debugf("cache get `%s`: hit", keyStr)
	return &session, nil
}

func (s *SingleKrItemStore) Put(k Key, session *Session) error {
	keyStr := k.Key()

	currentDb, err := s.getDb()
	if xerrors.Is(err, keyring.ErrKeyNotFound) || (currentDb != nil && currentDb.Sessions == nil) {
		log.Debugf("cache put: new db")
		currentDb = &singleKrItemDb{
			Sessions: map[string]Session{},
		}
	} else if err != nil {
		log.Debugf("cache put `%s`: error (reading): %s", keyStr, err)
		return xerrors.Errorf("loading db for %q: %w", keyStr, err)
	}

	currentDb.Sessions[keyStr] = *session

	bytes, err := json.Marshal(*currentDb)
	if err != nil {
		log.Debugf("cache put `%s`: error (marshalling): %s", keyStr, err)
		return xerrors.Errorf("marshalling db for %q: %w", keyStr, err)
	}

	// TODO: check that the db hasn't changed behind our backs
	// Unfortunately, it seems like keyring (and MacOS keychain in general)
	// offer no "check and set" operation that would guarantee this would work;
	// at best, we could only make the window smaller :/
	item := keyring.Item{
		Key:                         KeyringItemKey,
		Label:                       KeyringItemLabel,
		Data:                        bytes,
		KeychainNotTrustApplication: false,
	}
	if err := s.Keyring.Set(item); err != nil {
		log.Debugf("cache put `%s`: error (writing): %s", keyStr, err)
		return xerrors.Errorf("writing db for %q: %w", keyStr, err)
	}
	log.Debugf("cache put `%s`: success", keyStr)

	return nil
}
