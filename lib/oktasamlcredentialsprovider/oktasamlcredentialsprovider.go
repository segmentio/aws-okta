package oktasamlcredentialsprovider

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	awscredentials "github.com/aws/aws-sdk-go/aws/credentials"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	awsokta "github.com/segmentio/aws-okta/lib/v2"
	"github.com/segmentio/aws-okta/lib/v2/oktaclient"
	"github.com/segmentio/aws-okta/lib/v2/oktasamlcredentialsprovider/internal/oktasaml"
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

// TODO?
const ProviderName = "awsokta/oktasamlcredentialsprovider"

type Provider struct {
	OktaClient oktaclient.Client

	AWSSAMLURL string

	// Use this to choose an AssumableRole from a list
	TargetRoleARNChooser RoleChooser

	// Opts must have had ApplyDefaults and Validate called
	Opts Opts

	retrieved *sts.Credentials
}

// implements awscredentials.Provider

func (p *Provider) IsExpired() bool {
	if p.retrieved == nil {
		return true
	}
	expired := aws.TimeValue(p.retrieved.Expiration).Before(time.Now())
	p.Opts.Log.Debugf("IsExpired: %t", expired)
	return expired
}

// implements awscredentials.Expirer

func (p *Provider) ExpiresAt() time.Time {
	if p.retrieved == nil {
		// TODO: is this correct?
		return time.Time{}
	}
	p.Opts.Log.Debugf("ExpiresAt: %s", aws.TimeValue(p.retrieved.Expiration))
	return aws.TimeValue(p.retrieved.Expiration)
}

// TODO: needs testing
func (p *Provider) Retrieve() (awscredentials.Value, error) {
	if p.Opts.SessionCache != nil {
		// TODO check caching logic
		if r, isStatic := p.TargetRoleARNChooser.(StaticChooser); isStatic {
			k := sessionCacheKey{TargetRoleARN: r.RoleARN}
			if creds, err := p.Opts.SessionCache.Get(k); err != nil {
				p.Opts.Log.Infof("session cache hit: %s", k)
				return creds.Value, nil
			}
			p.Opts.Log.Infof("session cache miss: %s", k)
		}
	}

	cl := oktasaml.Client{
		OktaClient: p.OktaClient,
		SAMLURL:    p.AWSSAMLURL,
	}
	assumableRoles, err := cl.GetAssumableRoles()
	if err != nil {
		return awscredentials.Value{}, fmt.Errorf("fetching assumable roles: %w", err)
	}
	targetRole, err := p.TargetRoleARNChooser.Choose(assumableRoles)
	if err != nil {
		return awscredentials.Value{}, fmt.Errorf("choosing role: %w", err)
	}

	if p.Opts.SessionCache != nil {
		k := sessionCacheKey{TargetRoleARN: targetRole.Role}
		if creds, err := p.Opts.SessionCache.Get(k); err != nil {
			p.Opts.Log.Infof("session cache hit: %s", k)
			return creds.Value, nil
		}
		p.Opts.Log.Infof("session cache miss: %s", k)
	}

	sessConf := &aws.Config{}
	if p.Opts.Region != "" {
		p.Opts.Log.Debugf("using region: %s", p.Opts.Region)
		sessConf.Region = aws.String(p.Opts.Region)
	}
	sess := awssession.Must(awssession.NewSession(sessConf))

	svc := sts.New(sess)
	samlResponseB64, err := cl.GetSAMLResponseB64()
	if err != nil {
		return awscredentials.Value{}, fmt.Errorf("getting SAMLResponse: %w", err)
	}
	p.Opts.Log.Debugf("assuming role %s", targetRole.Role)
	resp, err := svc.AssumeRoleWithSAML(&sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(targetRole.Principal),
		RoleArn:         aws.String(targetRole.Role),
		SAMLAssertion:   aws.String(string(samlResponseB64)),
		DurationSeconds: aws.Int64(int64(p.Opts.SessionDuration.Seconds())),
	})
	if err != nil {
		return awscredentials.Value{}, fmt.Errorf("assuming role with SAML: %w", err)
	}

	creds := resp.Credentials
	credsValue := awscredentials.Value{
		AccessKeyID:     aws.StringValue(creds.AccessKeyId),
		SecretAccessKey: aws.StringValue(creds.SecretAccessKey),
		SessionToken:    aws.StringValue(creds.SessionToken),
		ProviderName:    ProviderName,
	}
	if p.Opts.SessionCache != nil {
		if err := p.Opts.SessionCache.Put(sessionCacheKey{TargetRoleARN: targetRole.Role}, sessionCacheValue{Value: credsValue}); err != nil {
			p.Opts.Log.Errorf("failed to put to session cache: %s", err)
		}
	}
	return credsValue, nil
}
