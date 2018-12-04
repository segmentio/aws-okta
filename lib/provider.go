package lib

import (
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	MaxSessionDuration    = time.Hour * 36
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour * 12

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

type ProviderOptions struct {
	MFADevice          string
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	Profiles           profiles
}

func (o ProviderOptions) Validate() error {
	if o.SessionDuration < MinSessionDuration {
		return errors.New("Minimum session duration is " + MinSessionDuration.String())
	} else if o.SessionDuration > MaxSessionDuration {
		return errors.New("Maximum session duration is " + MaxSessionDuration.String())
	}
	if o.AssumeRoleDuration < MinAssumeRoleDuration {
		return errors.New("Minimum duration for assumed roles is " + MinAssumeRoleDuration.String())
	} else if o.AssumeRoleDuration > MaxAssumeRoleDuration {
		log.Println(o.AssumeRoleDuration)
		return errors.New("Maximum duration for assumed roles is " + MaxAssumeRoleDuration.String())
	}

	return nil
}

func (o ProviderOptions) ApplyDefaults() ProviderOptions {
	if o.AssumeRoleDuration == 0 {
		o.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if o.SessionDuration == 0 {
		o.SessionDuration = DefaultSessionDuration
	}
	return o
}

type Provider struct {
	credentials.Expiry
	ProviderOptions
	profile                string
	expires                time.Time
	keyring                keyring.Keyring
	sessions               *KeyringSessions
	profiles               profiles
	defaultRoleSessionName string
}

func NewProvider(k keyring.Keyring, profile string, opts ProviderOptions) (*Provider, error) {
	opts = opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return &Provider{
		ProviderOptions: opts,
		keyring:         k,
		sessions:        &KeyringSessions{k, opts.Profiles},
		profile:         profile,
		profiles:        opts.Profiles,
	}, nil
}

func (p *Provider) Retrieve() (credentials.Value, error) {

	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	source := sourceProfile(p.profile, p.profiles)
	session, name, err := p.sessions.Retrieve(source, p.SessionDuration)
	p.defaultRoleSessionName = name
	if err != nil {
		session, err = p.getSamlSessionCreds()
		if err != nil {
			return credentials.Value{}, err
		}
		p.sessions.Store(source, p.roleSessionName(), session, p.SessionDuration)
	}

	log.Debugf(" Using session %s, expires in %s",
		(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
		session.Expiration.Sub(time.Now()).String())

	// If sourceProfile returns the same source then we do not need to assume a
	// second role. Not assuming a second role allows us to assume IDP enabled
	// roles directly.
	if p.profile != source {
		if role, ok := p.profiles[p.profile]["role_arn"]; ok {
			session, err = p.assumeRoleFromSession(session, role)
			if err != nil {
				return credentials.Value{}, err
			}

			log.Debugf("using role %s expires in %s",
				(*session.AccessKeyId)[len(*session.AccessKeyId)-4:],
				session.Expiration.Sub(time.Now()).String())
		}
	}

	p.SetExpiration(*session.Expiration, window)
	p.expires = *session.Expiration

	value := credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
		ProviderName:    "okta",
	}

	return value, nil
}

func (p *Provider) getSamlURL(source string) (string, error) {
	haystack := []string{p.profile, source, "okta"}
	for _, profile := range haystack {
		oktaAwsSAMLUrl, ok := p.profiles[profile]["aws_saml_url"]
		if ok {
			log.Debugf("Using aws_saml_url from profile: %s", profile)
			return oktaAwsSAMLUrl, nil
		}
	}
	return "", errors.New("aws_saml_url missing from ~/.aws/config")
}

func (p *Provider) getOktaSessionCookieKey(source string) string {
	haystack := []string{p.profile, source, "okta"}
	for _, profile := range haystack {
		oktaSessionCookieKey, ok := p.profiles[profile]["okta_session_cookie_key"]
		if ok {
			log.Debugf("Using okta_session_cookie_key from profile: %s", profile)
			return oktaSessionCookieKey
		}
	}
	return "okta-session-cookie"
}

func (p *Provider) getSamlSessionCreds() (sts.Credentials, error) {
	source := sourceProfile(p.profile, p.profiles)
	oktaAwsSAMLUrl, err := p.getSamlURL(source)
	if err != nil {
		return sts.Credentials{}, err
	}
	oktaSessionCookieKey := p.getOktaSessionCookieKey(source)

	profileARN, ok := p.profiles[source]["role_arn"]
	if !ok {
		return sts.Credentials{}, errors.New("Source profile must provide `role_arn`")
	}

	provider := OktaProvider{
		MFADevice:            p.ProviderOptions.MFADevice,
		Keyring:              p.keyring,
		ProfileARN:           profileARN,
		SessionDuration:      p.SessionDuration,
		OktaAwsSAMLUrl:       oktaAwsSAMLUrl,
		OktaSessionCookieKey: oktaSessionCookieKey,
	}

	creds, oktaUsername, err := provider.Retrieve()
	if err != nil {
		return sts.Credentials{}, err
	}
	p.defaultRoleSessionName = oktaUsername

	return creds, nil
}

// assumeRoleFromSession takes a session created with an okta SAML login and uses that to assume a role
func (p *Provider) assumeRoleFromSession(creds sts.Credentials, roleArn string) (sts.Credentials, error) {
	client := sts.New(session.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
		*creds.AccessKeyId,
		*creds.SecretAccessKey,
		*creds.SessionToken,
	)}))

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.AssumeRoleDuration.Seconds())),
	}

	log.Debugf("Assuming role %s from session token", roleArn)
	resp, err := client.AssumeRole(input)
	if err != nil {
		return sts.Credentials{}, err
	}

	return *resp.Credentials, nil
}

func (p *Provider) roleSessionName() string {
	if name := p.profiles[p.profile]["role_session_name"]; name != "" {
		return name
	}

	if p.defaultRoleSessionName != "" {
		return p.defaultRoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}
