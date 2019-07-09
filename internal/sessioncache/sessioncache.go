// sessioncache caches sessions (sts.Credentials)
//
// sessioncache splits Stores (the way cache items are stored) from Keys
// (the way cache items are looked up/replaced)
package sessioncache

import (
	"encoding/json"
	"errors"

	"github.com/aws/aws-sdk-go/service/sts"
)

// Session adds a session name to sts.Credentials
type Session struct {
	Name string
	sts.Credentials
}

func (s *Session) Bytes() ([]byte, error) {
	return json.Marshal(s)
}

// Key is used to compute the cache key for a session
type Key interface {
	Key() string
}

var ErrSessionExpired = errors.New("session expired")
