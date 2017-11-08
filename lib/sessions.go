package lib

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/sts"
)

type KeyringSessions struct {
	Keyring  keyring.Keyring
	Profiles profiles
}

func NewKeyringSessions(k keyring.Keyring, p profiles) (*KeyringSessions, error) {
	return &KeyringSessions{
		Keyring:  k,
		Profiles: p,
	}, nil
}

func (s *KeyringSessions) key(profile string, duration time.Duration) string {
	source := sourceProfile(profile, s.Profiles)
	hasher := md5.New()
	hasher.Write([]byte(duration.String()))

	if p, ok := s.Profiles[profile]; ok {
		enc := json.NewEncoder(hasher)
		enc.Encode(p)
	}

	return fmt.Sprintf("%s session (%x)", source, hex.EncodeToString(hasher.Sum(nil))[0:10])
}

func (s *KeyringSessions) Retrieve(profile string, duration time.Duration) (session sts.Credentials, err error) {
	item, err := s.Keyring.Get(s.key(profile, duration))
	if err != nil {
		return session, err
	}

	if err = json.Unmarshal(item.Data, &session); err != nil {
		return session, err
	}

	if session.Expiration.Before(time.Now()) {
		return session, errors.New("Session is expired")
	}

	return
}

func (s *KeyringSessions) Store(profile string, session sts.Credentials, duration time.Duration) error {
	bytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	log.Debugf("Writing session for %s to keyring", profile)
	s.Keyring.Set(keyring.Item{
		Key:       s.key(profile, duration),
		Label:     "aws-vault session for " + profile,
		Data:      bytes,
		TrustSelf: true,
	})

	return nil
}

func (s *KeyringSessions) Delete(profile string) (n int, err error) {
	keys, err := s.Keyring.Keys()
	if err != nil {
		return n, err
	}

	for _, k := range keys {
		if strings.HasPrefix(k, fmt.Sprintf("%s session", sourceProfile(profile, s.Profiles))) {
			if err = s.Keyring.Remove(k); err != nil {
				return n, err
			}
			n++
		}
	}

	return
}
