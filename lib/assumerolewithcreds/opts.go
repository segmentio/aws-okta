package assumerolewithcreds

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	MinAssumeRoleDuration     = time.Minute * 15
	MaxAssumeRoleDuration     = time.Hour * 12
	DefaultAssumeRoleDuration = time.Minute * 15
)

type Opts struct {
	AssumeRoleDuration time.Duration

	// if unset, no session caching will be done
	SessionCache SessionCache

	Log *logrus.Logger

	RoleSessionName string
}

func (o *Opts) ApplyDefaults() *Opts {
	if o.AssumeRoleDuration == 0 {
		o.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if o.Log == nil {
		o.Log = logrus.StandardLogger()
	}
	return o
}

type ErrAssumeRoleDurationOOB struct {
	Min    time.Duration
	Max    time.Duration
	Actual time.Duration
}

func (e *ErrAssumeRoleDurationOOB) Error() string {
	if e.Actual < e.Min {
		return fmt.Sprintf("actual AssumeRoleDuration %s < minimum %s", e.Actual, e.Min)
	}
	return fmt.Sprintf("actual AssumeRoleDuration %s > maximum %s", e.Actual, e.Max)
}

func (o *Opts) Validate() error {
	if o.AssumeRoleDuration < MinAssumeRoleDuration || o.AssumeRoleDuration > MaxAssumeRoleDuration {
		return &ErrAssumeRoleDurationOOB{
			Min:    MinAssumeRoleDuration,
			Max:    MaxAssumeRoleDuration,
			Actual: o.AssumeRoleDuration,
		}
	}
	return nil
}
