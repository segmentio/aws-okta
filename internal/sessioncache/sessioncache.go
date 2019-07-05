package sessioncache

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/service/sts"
)

type Session struct {
	Name string
	sts.Credentials
}

func (s *Session) Bytes() ([]byte, error) {
	return json.Marshal(s)
}

type Key interface {
	Key() string
}
