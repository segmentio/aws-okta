package sessioncache

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
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

func (s *SingleKrItemStore) getDb() (*singleKrItemDb, error) {
	item, err := s.Keyring.Get(KeyringItemKey)

	if err != nil {
		return nil, err
	}

	var unmarshalled singleKrItemDb
	if err := json.Unmarshal(item.Data, &unmarshalled); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall db from keyring item")
	}

	return &unmarshalled, nil
}

func (s *SingleKrItemStore) Get(k Key) (*Session, error) {
	keyStr := k.Key()

	currentDb, err := s.getDb()
	if err != nil {
		log.Debugf("cache get `%s`: miss (read error): %s", keyStr, err)
		return nil, err
	}

	session, ok := currentDb.Sessions[keyStr]
	if !ok {
		log.Debugf("cache get `%s`: miss", keyStr)
		return nil, errors.New("Session not found")
	}

	if session.Expiration.Before(time.Now()) {
		log.Debugf("cache get `%s`: expired", keyStr)
		return nil, errors.New("Session expired")
	}

	log.Debugf("cache get `%s`: hit", keyStr)
	return &session, nil
}

func (s *SingleKrItemStore) Put(k Key, session *Session) error {
	keyStr := k.Key()

	currentDb, err := s.getDb()
	if err == keyring.ErrKeyNotFound || currentDb.Sessions == nil {
		log.Debugf("cache put: new db")
		currentDb = &singleKrItemDb{
			Sessions: map[string]Session{},
		}
	} else if err != nil {
		log.Debugf("cache put `%s`: error (reading): %s", keyStr, err)
		return err
	}

	currentDb.Sessions[keyStr] = *session

	bytes, err := json.Marshal(*currentDb)
	if err != nil {
		log.Debugf("cache put `%s`: error (marshalling): %s", keyStr, err)
		return err
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
		return err
	}
	log.Debugf("cache put `%s`: success", keyStr)

	return nil
}
