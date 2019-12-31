package assumerolewithsaml

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	MaxSessionDuration = time.Hour * 24 * 90
	MinSessionDuration = time.Minute * 15

	DefaultSessionDuration = time.Hour * 4
)

type Opts struct {
	SessionDuration time.Duration

	// if unset, no session caching will be done
	SessionCache SessionCache

	Log *logrus.Logger

	// TODO: parse from SAML assertion?
	RoleSessionName string

	Region string
}

func (o *Opts) ApplyDefaults() *Opts {
	if o.SessionDuration == 0 {
		o.SessionDuration = DefaultSessionDuration
	}
	if o.Log == nil {
		o.Log = logrus.StandardLogger()
	}
	return o
}

type ErrSessionDurationOOB struct {
	Min    time.Duration
	Max    time.Duration
	Actual time.Duration
}

func (e *ErrSessionDurationOOB) Error() string {
	if e.Actual < e.Min {
		return fmt.Sprintf("actual SessionDuration %s < minimum %s", e.Actual, e.Min)
	}
	return fmt.Sprintf("actual SessionDuration %s > maximum %s", e.Actual, e.Max)
}

func (o *Opts) Validate() error {
	if o.SessionDuration < MinSessionDuration || o.SessionDuration > MaxSessionDuration {
		return &ErrSessionDurationOOB{
			Min:    MinSessionDuration,
			Max:    MaxSessionDuration,
			Actual: o.SessionDuration,
		}
	}
	return nil
}
