package assumerolewithsaml

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	awsokta "github.com/segmentio/aws-okta/lib/v2"
	"github.com/segmentio/aws-okta/lib/v2/assumerolewithsaml/internal/oktasaml"
	"github.com/segmentio/aws-okta/lib/v2/oktaclient"
)

type RoleChooser interface {
	Choose([]awsokta.AssumableRole) (awsokta.AssumableRole, error)
}

type StaticChooser struct {
	RoleARN string
}

type ErrRoleNotFound struct {
	RoleARN string
}

func (e *ErrRoleNotFound) Error() string {
	return fmt.Sprintf("role not found %s", e.RoleARN)
}

func (c StaticChooser) Choose(roles []awsokta.AssumableRole) (awsokta.AssumableRole, error) {
	for _, r := range roles {
		if r.Role == c.RoleARN {
			return r, nil
		}
	}
	return awsokta.AssumableRole{}, &ErrRoleNotFound{RoleARN: c.RoleARN}
}

type AssumeRoleWithSAML struct {
	OktaClient oktaclient.Client

	AWSSAMLURL string

	// Use this to choose an AssumableRole from a list
	TargetRoleARNChooser RoleChooser

	// Opts must have had ApplyDefaults and Validate called
	Opts Opts
}

type CredsMeta struct {
	Region string
}

type Creds struct {
	CredsMeta
	awsokta.AWSCreds
}

// TODO: needs testing
func (a AssumeRoleWithSAML) Assume() (Creds, error) {
	if a.Opts.SessionCache != nil {
		// TODO check caching logic
		if r, isStatic := a.TargetRoleARNChooser.(StaticChooser); isStatic {
			k := sessionCacheKey{TargetRoleARN: r.RoleARN}
			if creds, err := a.Opts.SessionCache.Get(k); err != nil {
				a.Opts.Log.Infof("session cache hit: %s", k)
				return creds, nil
			}
			a.Opts.Log.Infof("session cache miss: %s", k)
		}
	}

	cl := oktasaml.Client{
		OktaClient: a.OktaClient,
		SAMLURL:    a.AWSSAMLURL,
	}
	assumableRoles, err := cl.GetAssumableRoles()
	if err != nil {
		return Creds{}, fmt.Errorf("fetching assumable roles: %w", err)
	}
	targetRole, err := a.TargetRoleARNChooser.Choose(assumableRoles)
	if err != nil {
		return Creds{}, fmt.Errorf("choosing role: %w", err)
	}

	if a.Opts.SessionCache != nil {
		k := sessionCacheKey{TargetRoleARN: targetRole.Role}
		if creds, err := a.Opts.SessionCache.Get(k); err != nil {
			a.Opts.Log.Infof("session cache hit: %s", k)
			return creds, nil
		}
		a.Opts.Log.Infof("session cache miss: %s", k)
	}

	sessConf := &aws.Config{}
	if a.Opts.Region != "" {
		a.Opts.Log.Debugf("using region: %s", a.Opts.Region)
		sessConf.Region = aws.String(a.Opts.Region)
	}
	sess := awssession.Must(awssession.NewSession(sessConf))

	svc := sts.New(sess)
	samlResponseB64, err := cl.GetSAMLResponseB64()
	if err != nil {
		return Creds{}, fmt.Errorf("getting SAMLResponse: %w", err)
	}
	a.Opts.Log.Debugf("assuming role %s", targetRole.Role)
	resp, err := svc.AssumeRoleWithSAML(&sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(targetRole.Principal),
		RoleArn:         aws.String(targetRole.Role),
		SAMLAssertion:   aws.String(string(samlResponseB64)),
		DurationSeconds: aws.Int64(int64(a.Opts.SessionDuration.Seconds())),
	})
	if err != nil {
		return Creds{}, fmt.Errorf("assuming role with SAML: %w", err)
	}

	creds := Creds{
		// TODO
		CredsMeta: CredsMeta{
			Region: a.Opts.Region,
		},
		AWSCreds: awsokta.AWSCreds{
			AccessKeyID:     *resp.Credentials.AccessKeyId,
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			SessionToken:    *resp.Credentials.SessionToken,
		},
	}
	if a.Opts.SessionCache != nil {
		if err := a.Opts.SessionCache.Put(sessionCacheKey{TargetRoleARN: targetRole.Role}, creds); err != nil {
			a.Opts.Log.Errorf("failed to put to session cache: %s", err)
		}
	}
	return creds, nil
}
