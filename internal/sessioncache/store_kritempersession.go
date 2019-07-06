package sessioncache

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
)

type KrItemPerSessionStore struct {
	Keyring keyring.Keyring
}

func (s *KrItemPerSessionStore) Get(k Key) (*Session, error) {
	keyStr := k.Key()
	item, err := s.Keyring.Get(keyStr)
	if err != nil {
		log.Debugf("cache get `%s`: miss (read error): %s", keyStr, err)
		return nil, err
	}

	var session Session

	if err = json.Unmarshal(item.Data, &session); err != nil {
		log.Debugf("cache get `%s`: miss (unmarshal error): %s", keyStr, err)
		return nil, err
	}

	if session.Expiration.Before(time.Now()) {
		log.Debugf("cache get `%s`: expired", keyStr)
		return nil, errors.New("Session is expired")
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
