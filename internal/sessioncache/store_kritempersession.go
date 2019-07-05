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
	item, err := s.Keyring.Get(k.Key())
	if err != nil {
		return nil, err
	}

	var session Session

	if err = json.Unmarshal(item.Data, &session); err != nil {
		return nil, err
	}

	if session.Expiration.Before(time.Now()) {
		return nil, errors.New("Session is expired")
	}

	return &session, nil
}

func (s *KrItemPerSessionStore) Put(k Key, session *Session) error {
	bytes, err := session.Bytes()
	if err != nil {
		return err
	}

	log.Debugf("Writing session for %s to keyring", session.Name)
	s.Keyring.Set(keyring.Item{
		Key:                         k.Key(),
		Label:                       "aws session for " + session.Name,
		Data:                        bytes,
		KeychainNotTrustApplication: false,
	})

	return nil
}
