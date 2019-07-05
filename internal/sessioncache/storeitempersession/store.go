package storeitempersession

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/internal/sessioncache"
	"github.com/segmentio/kit/log"
)

type Store struct {
	Keyring keyring.Keyring
}

func New(k keyring.Keyring) (*Store, error) {
	return &Store{
		Keyring: k,
	}, nil
}

func (s *Store) Get(k sessioncache.Key) (*sessioncache.Session, error) {
	item, err := s.Keyring.Get(k.Key())
	if err != nil {
		return nil, err
	}

	var session sessioncache.Session

	if err = json.Unmarshal(item.Data, &session); err != nil {
		return nil, err
	}

	if session.Expiration.Before(time.Now()) {
		return nil, errors.New("Session is expired")
	}

	return &session, nil
}

func (s *Store) Put(k sessioncache.Key, session *sessioncache.Session) error {
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
