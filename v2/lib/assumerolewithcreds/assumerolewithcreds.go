package assumerolewithcreds

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	awsokta "github.com/segmentio/aws-okta/v2/lib"
)

type AssumeRoleWithCreds struct {
	BaseRoleCreds awsokta.AWSCreds
	TargetRoleARN string
	// TODO: prompter?

	// Opts must have had ApplyDefaults and Validate called
	Opts Opts
}

type CredsMeta struct {
	// TODO
}

type Creds struct {
	CredsMeta
	awsokta.AWSCreds
}

// TODO: needs testing
func (a AssumeRoleWithCreds) Assume() (Creds, error) {
	if a.Opts.SessionCache != nil {
		k := sessionCacheKey{TargetRoleARN: r.TargetRoleARN}
		if creds, err := a.Opts.SessionCache.Get(k); err != nil {
			r.Opts.Log.Infof("session cache hit: %s", k)
			return creds, nil
		}
		r.Opts.Log.Infof("session cache miss: %s", k)
	}
	sess, err := awssession.NewSession(
		&aws.Config{
			Credentials: credentials.NewStaticCredentials(
				a.BaseRoleCreds.AccessKeyID,
				a.BaseRoleCreds.SecretAccessKey,
				a.BaseRoleCreds.SessionToken,
			),
		},
	)
	if err != nil {
		return Creds{}, err
	}

	cl := sts.New(sess)

	a.Opts.Log.Debugf("assuming role %s", a.TargetRoleARN)
	var roleSessionName = a.Opts.RoleSessionName
	if roleSessionName == "" {
		// generate a role session name from a timestamp
		roleSessionName = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	resp, err := cl.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         aws.String(a.TargetRoleARN),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int64(int64(a.Opts.AssumeRoleDuration.Seconds())),
	})
	if err != nil {
		return Creds{}, err
	}

	creds := Creds{
		// TODO
		CredsMeta: CredsMeta{},
		AWSCreds: awsokta.AWSCreds{
			AccessKeyID:     *resp.Credentials.AccessKeyId,
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			SessionToken:    *resp.Credentials.SessionToken,
		},
	}
	if r.Opts.SessionCache != nil {
		if err := r.Opts.SessionCache.Put(sessionCacheKey{TargetRoleARN: a.TargetRoleARN}, creds); err != nil {
			r.Opts.Log.Errorf("failed to put to session cache: %s", err)
		}
	}
	return creds, nil
}
