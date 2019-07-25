package lib

import (
	"fmt"
	"net/url"
	"time"

	"errors"

	"github.com/segmentio/aws-okta/internal/sessioncache"
	log "github.com/sirupsen/logrus"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	// use xerrors until 1.13 is stable/oldest supported version
	"golang.org/x/xerrors"
)

const (
	MaxSessionDuration    = time.Hour * 24 * 90
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour * 12

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

type ProviderOptions struct {
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	Profiles           Profiles
	MFAConfig          MFAConfig

	// if true, use store_singlekritem SessionCache (new)
	// if false, use store_kritempersession SessionCache (old)
	SessionCacheSingleItem bool
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

type SessionCacheInterface interface {
	Get(sessioncache.Key) (*sessioncache.Session, error)
	Put(sessioncache.Key, *sessioncache.Session) error
}

type Provider struct {
	credentials.Expiry
	ProviderOptions
	profile                string
	expires                time.Time
	keyring                keyring.Keyring
	sessions               SessionCacheInterface
	profiles               Profiles
	defaultRoleSessionName string
}

func NewProvider(k keyring.Keyring, profile string, opts ProviderOptions) (*Provider, error) {
	opts = opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	var sessions SessionCacheInterface

	if opts.SessionCacheSingleItem {
		log.Debugf("Using SingleKrItemStore")
		sessions = &sessioncache.SingleKrItemStore{k}
	} else {
		log.Debugf("Using KrItemPerSessionStore")
		sessions = &sessioncache.KrItemPerSessionStore{k}
	}

	return &Provider{
		ProviderOptions: opts,
		keyring:         k,
		sessions:        sessions,
		profile:         profile,
		profiles:        opts.Profiles,
	}, nil
}

func (p *Provider) Retrieve() (credentials.Value, error) {

	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	// TODO(nick): why are we using the source profile name and not the actual profile's name?
	source := sourceProfile(p.profile, p.profiles)
	profileConf, ok := p.profiles[p.profile]
	if !ok {
		return credentials.Value{}, fmt.Errorf("missing profile named %s", p.profile)
	}
	key := sessioncache.OrigKey{
		ProfileName: source,
		ProfileConf: profileConf,
		Duration:    p.SessionDuration,
	}

	var creds sts.Credentials
	if cachedSession, err := p.sessions.Get(key); err != nil {
		creds, err = p.getSamlSessionCreds()
		if err != nil {
			return credentials.Value{}, xerrors.Errorf("getting creds via SAML: %w", err)
		}
		newSession := sessioncache.Session{
			Name:        p.roleSessionName(),
			Credentials: creds,
		}
		if err = p.sessions.Put(key, &newSession); err != nil {
			return credentials.Value{}, xerrors.Errorf("putting to sessioncache", err)
		}

		// TODO(nick): not really clear why this is done
		p.defaultRoleSessionName = newSession.Name
	} else {
		creds = cachedSession.Credentials
		p.defaultRoleSessionName = cachedSession.Name
	}

	log.Debugf("Using session %s, expires in %s",
		(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
		creds.Expiration.Sub(time.Now()).String())

	// If sourceProfile returns the same source then we do not need to assume a
	// second role. Not assuming a second role allows us to assume IDP enabled
	// roles directly.
	if p.profile != source {
		if role, ok := p.profiles[p.profile]["role_arn"]; ok {
			var err error
			creds, err = p.assumeRoleFromSession(creds, role)
			if err != nil {
				return credentials.Value{}, err
			}

			log.Debugf("using role %s expires in %s",
				(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
				creds.Expiration.Sub(time.Now()).String())
		}
	}

	p.SetExpiration(*(creds.Expiration), window)
	p.expires = *(creds.Expiration)

	value := credentials.Value{
		AccessKeyID:     *(creds.AccessKeyId),
		SecretAccessKey: *(creds.SecretAccessKey),
		SessionToken:    *(creds.SessionToken),
		ProviderName:    "okta",
	}

	return value, nil
}

func (p *Provider) getSamlURL() (string, error) {
	oktaAwsSAMLUrl, profile, err := p.profiles.GetValue(p.profile, "aws_saml_url")
	if err != nil {
		return "", errors.New("aws_saml_url missing from ~/.aws/config")
	}
	log.Debugf("Using aws_saml_url from profile: %s", profile)
	return oktaAwsSAMLUrl, nil
}

func (p *Provider) getOktaSessionCookieKey() string {
	oktaSessionCookieKey, profile, err := p.profiles.GetValue(p.profile, "okta_session_cookie_key")
	if err != nil {
		return "okta-session-cookie"
	}
	log.Debugf("Using okta_session_cookie_key from profile: %s", profile)
	return oktaSessionCookieKey
}

func (p *Provider) getSamlSessionCreds() (sts.Credentials, error) {
	source := sourceProfile(p.profile, p.profiles)
	oktaAwsSAMLUrl, err := p.getSamlURL()
	if err != nil {
		return sts.Credentials{}, err
	}
	oktaSessionCookieKey := p.getOktaSessionCookieKey()

	profileARN, ok := p.profiles[source]["role_arn"]
	if !ok {
		return sts.Credentials{}, errors.New("Source profile must provide `role_arn`")
	}

	provider := OktaProvider{
		MFAConfig:            p.ProviderOptions.MFAConfig,
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

func (p *Provider) GetSAMLLoginURL() (*url.URL, error) {
	source := sourceProfile(p.profile, p.profiles)
	oktaAwsSAMLUrl, err := p.getSamlURL()
	if err != nil {
		return &url.URL{}, err
	}
	oktaSessionCookieKey := p.getOktaSessionCookieKey()

	profileARN, ok := p.profiles[source]["role_arn"]
	if !ok {
		return &url.URL{}, errors.New("Source profile must provide `role_arn`")
	}

	provider := OktaProvider{
		MFAConfig:            p.ProviderOptions.MFAConfig,
		Keyring:              p.keyring,
		ProfileARN:           profileARN,
		SessionDuration:      p.SessionDuration,
		OktaAwsSAMLUrl:       oktaAwsSAMLUrl,
		OktaSessionCookieKey: oktaSessionCookieKey,
	}

	loginURL, err := provider.GetSAMLLoginURL()
	if err != nil {
		return &url.URL{}, err
	}
	return loginURL, nil
}

// assumeRoleFromSession takes a session created with an okta SAML login and uses that to assume a role
func (p *Provider) assumeRoleFromSession(creds sts.Credentials, roleArn string) (sts.Credentials, error) {
	client := sts.New(aws_session.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
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

// roleSessionName returns the profile's `role_session_name` if set, or the
// provider's defaultRoleSessionName if set. If neither is set, returns some
// arbitrary unique string
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
