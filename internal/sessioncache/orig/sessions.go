package orig

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/sts"
)

type awsSession struct {
	sts.Credentials
	Name string
}

type SessionCache struct {
	Keyring  keyring.Keyring
	Profiles map[string]map[string]string
}

// sourceProfile returns either the defined source_profile or p if none exists
//
// copied from lib; this will go away shortly
func sourceProfile(p string, from map[string]map[string]string) string {
	if conf, ok := from[p]; ok {
		if source := conf["source_profile"]; source != "" {
			return source
		}
	}
	return p
}

func New(k keyring.Keyring, p map[string]map[string]string) (*SessionCache, error) {
	return &SessionCache{
		Keyring: k,
	}, nil
}

// key returns a key for the keyring item. This is a string containing the source profile name,
// the profile name, and a hash of the duration
//
// this is a copy of KeyringSessions.key and should preserve behavior, *except* that it assumes `profileName`
// is a valid and existing profile name
func key(profileName string, profileConf map[string]string, duration time.Duration) string {
	// nick: I don't understand this at all. This key function is roughly:
	// sourceProfileName + hex(md5(duration + json(profileConf)))
	// - why md5?
	// - why the JSON of the whole profile? (especially strange considering JSON map order is undetermined)
	// TODO(nick): document this
	var source string
	if source = profileConf["source_profile"]; source != "" {
		source = profileName
	}
	hasher := md5.New()
	hasher.Write([]byte(duration.String()))

	enc := json.NewEncoder(hasher)
	enc.Encode(profileConf)

	return fmt.Sprintf("%s session (%x)", source, hex.EncodeToString(hasher.Sum(nil))[0:10])
}

func (s *SessionCache) Retrieve(profileName string, profileConf map[string]string, duration time.Duration) (sts.Credentials, string, error) {
	var session awsSession
	item, err := s.Keyring.Get(key(profileName, profileConf, duration))
	if err != nil {
		return session.Credentials, session.Name, err
	}

	if err = json.Unmarshal(item.Data, &session); err != nil {
		return session.Credentials, session.Name, err
	}

	if session.Expiration.Before(time.Now()) {
		return session.Credentials, session.Name, errors.New("Session is expired")
	}

	return session.Credentials, session.Name, nil
}

func (s *SessionCache) Store(profileName string, profileConf map[string]string, sessionName string, creds sts.Credentials, duration time.Duration) error {
	session := awsSession{Credentials: creds, Name: sessionName}
	bytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	log.Debugf("Writing session for %s to keyring", profileName)
	s.Keyring.Set(keyring.Item{
		Key:                         key(profileName, profileConf, duration),
		Label:                       "aws session for " + profileName,
		Data:                        bytes,
		KeychainNotTrustApplication: false,
	})

	return nil
}

func (s *SessionCache) Delete(profileName string, profileConf map[string]string) (n int, err error) {
	keys, err := s.Keyring.Keys()
	if err != nil {
		return n, err
	}

	for _, k := range keys {
		var source string
		if source = profileConf["source_profile"]; source != "" {
			source = profileName
		}
		if strings.HasPrefix(k, fmt.Sprintf("%s session", source)) {
			if err = s.Keyring.Remove(k); err != nil {
				return n, err
			}
			n++
		}
	}

	return
}
