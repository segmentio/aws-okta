// manages auth sessions for Okta applications
package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/segmentio/aws-okta/lib/session"
	"github.com/segmentio/aws-okta/profiles"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	aws_session "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"

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

type SessionCacheInterface interface {
	Get(session.Key) (*session.Session, error)
	Put(session.Key, *session.Session) error
}

type OktaClient interface {
	AuthenticateUser() error
	GetSessionToken() string
	Request(method string, path string, queryParams url.Values, data []byte, format string, followRedirects bool) (*http.Response, error)
	GetURL(string) (*url.URL, error)
}

type SAMLRoleSelection interface {
	ChooseRole(roles []AssumableRole) (int, error)
}

type AWSSAMLProvider struct {
	credentials.Expiry
	AWSSAMLProviderOptions
	oktaClient             OktaClient
	profileARN             string
	oktaAWSSAMLURL         string
	oktaAccountName        string
	awsRegion              string
	profile                string
	Expires                time.Time
	sessions               SessionCacheInterface
	defaultRoleSessionName string
	selector               SAMLRoleSelection
}

type AWSSAMLProviderOptions struct {
	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	ExpiryWindow       time.Duration
	Profiles           profiles.Profiles
	AssumeRoleArn      string

	// this option is deprecated.
	// It will be ignored.
	SessionCacheSingleItem bool
}

// validates aws saml configuration options.
func (o *AWSSAMLProviderOptions) Validate() error {
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

// updates aws saml configuration with package provided defaults.
func (o *AWSSAMLProviderOptions) ApplyDefaults() {
	if o.AssumeRoleDuration == 0 {
		o.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if o.SessionDuration == 0 {
		o.SessionDuration = DefaultSessionDuration
	}
}

// creates a new AWS saml provider
func NewAWSSAMLProvider(sessions SessionCacheInterface, profile string, opts AWSSAMLProviderOptions, oktaClient OktaClient, selector SAMLRoleSelection) (*AWSSAMLProvider, error) {
	var profileARN string
	var err error

	opts.ApplyDefaults()
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	log.Debug("Provider Option is deprecated: SessionCacheSingleItem")

	source := profiles.SourceProfile(profile, opts.Profiles)

	// if the assumable role is passed it have it override what is in the profile
	if opts.AssumeRoleArn != "" {
		profileARN = opts.AssumeRoleArn
		log.Debug("Overriding Assumable role with: ", profileARN)
	} else {
		// if `role_arn` isn't provided as part of the profile we can still prompt
		// for it later after we get the saml assertion and know all the roles the
		// user can assume.
		profileARN = opts.Profiles[source]["role_arn"]
	}

	provider := AWSSAMLProvider{
		AWSSAMLProviderOptions: opts,
		oktaClient:             oktaClient,
		profileARN:             profileARN,
		sessions:               sessions,
		profile:                profile,
		selector:               selector,
	}

	if region := opts.Profiles[source]["region"]; region != "" {
		provider.awsRegion = region
	}
	err = provider.getSAMLURL()
	if err != nil {
		return nil, err
	}
	return &provider, nil
}

// Gets a set of STS credentials to access AWS services.
func (p *AWSSAMLProvider) Retrieve() (credentials.Value, error) {
	window := p.ExpiryWindow
	if window == 0 {
		window = time.Minute * 5
	}

	// TODO(nick): why are we using the source profile name and not the actual profile's name?
	source := profiles.SourceProfile(p.profile, p.Profiles)
	profileConf, ok := p.Profiles[p.profile]
	if !ok {
		return credentials.Value{}, fmt.Errorf("missing profile named %s", p.profile)
	}
	key := session.KeyWithProfileARN{
		ProfileName: source,
		ProfileConf: profileConf,
		Duration:    p.SessionDuration,
		ProfileARN:  p.AssumeRoleArn,
	}

	var creds sts.Credentials
	if cachedSession, err := p.sessions.Get(key); err != nil {
		creds, err = p.getSAMLSessionCreds()
		if err != nil {
			return credentials.Value{}, xerrors.Errorf("getting creds via SAML: %w", err)
		}
		newSession := session.Session{
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
		time.Until(*creds.Expiration).String())

	// If SourceProfile returns the same source then we do not need to assume a
	// second role. Not assuming a second role allows us to assume IDP enabled
	// roles directly.
	if p.profile != source {
		if role, ok := p.Profiles[p.profile]["role_arn"]; ok {
			var err error
			creds, err = p.assumeRoleFromSession(creds, role)
			if err != nil {
				return credentials.Value{}, err
			}

			log.Debugf("using role %s expires in %s",
				(*(creds.AccessKeyId))[len(*(creds.AccessKeyId))-4:],
				time.Until(*creds.Expiration).String())
		}
	}

	p.SetExpiration(*(creds.Expiration), window)
	p.Expires = *(creds.Expiration)

	value := credentials.Value{
		AccessKeyID:     *(creds.AccessKeyId),
		SecretAccessKey: *(creds.SecretAccessKey),
		SessionToken:    *(creds.SessionToken),
		ProviderName:    "okta",
	}

	return value, nil
}

// GetRoleARN uses temporary credentials to call AWS's get-caller-identity and
// returns the assumed role's ARN
func (p *AWSSAMLProvider) GetRoleARNWithRegion(creds credentials.Value) (string, error) {
	config := aws.Config{Credentials: credentials.NewStaticCredentials(
		creds.AccessKeyID,
		creds.SecretAccessKey,
		creds.SessionToken,
	)}
	if region := p.Profiles[profiles.SourceProfile(p.profile, p.Profiles)]["region"]; region != "" {
		config.WithRegion(region)
	}
	awsSession, err := aws_session.NewSession(&config)
	if err != nil {
		return "", err
	}
	client := sts.New(awsSession)

	indentity, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Errorf("Error getting caller identity: %s", err.Error())
		return "", err
	}
	arn := *indentity.Arn
	return arn, nil
}

// get the AWS saml url path from the AWS profile and store it in the provider
// struct.
//
// uses the `aws_saml_url` to search for the url in the profile. If the url
// doesn't exist in the profile an error is returned.
func (p *AWSSAMLProvider) getSAMLURL() error {
	oktaAWSSAMLURL, profile, err := p.Profiles.GetValue(p.profile, "aws_saml_url")
	if err != nil {
		return errors.New("aws_saml_url missing from ~/.aws/config")
	}
	log.Debugf("Using aws_saml_url from profile %s: %s", profile, oktaAWSSAMLURL)
	p.oktaAWSSAMLURL = oktaAWSSAMLURL
	return nil
}

// gets the Okta session cookie key from the profile or returns the default
// value if the profile doesn't exist. The provider struct is not modified by
// this method.
func (p *AWSSAMLProvider) getOktaSessionCookieKey() string {
	oktaSessionCookieKey, profile, err := p.Profiles.GetValue(p.profile, "okta_session_cookie_key")
	if err != nil {
		return "okta-session-cookie"
	}
	log.Debugf("Using okta_session_cookie_key from profile: %s", profile)
	return oktaSessionCookieKey
}

// get the Okta account name from the AWS profile and returns it to the caller.
// if no account name is found in the profile the default value of `okta-creds`
// is used.
//
// the provider struct is not modified by this method.
func (p *AWSSAMLProvider) getOktaAccountName() string {
	oktaAccountName, profile, err := p.Profiles.GetValue(p.profile, "okta_account_name")
	if err != nil {
		return "okta-creds"
	}
	log.Debugf("Using okta_account_name: %s from profile: %s", oktaAccountName, profile)
	return "okta-creds-" + oktaAccountName
}

// get a set of AWS STS credentials.
func (p *AWSSAMLProvider) getSAMLSessionCreds() (sts.Credentials, error) {
	log.Debugf("Using okta provider (%s)", p.oktaAccountName)
	creds, err := p.authenticateProfileWithRegion(p.profileARN, p.SessionDuration, p.oktaAWSSAMLURL, p.awsRegion)
	if err != nil {
		return sts.Credentials{}, err
	}

	//	p.defaultRoleSessionName = p.oktaClient.oktaCreds.Username

	return creds, nil
}

// assumeRoleFromSession takes a session created with an okta SAML login and uses that to assume a role
func (p *AWSSAMLProvider) assumeRoleFromSession(creds sts.Credentials, roleArn string) (sts.Credentials, error) {
	awsSession, err := aws_session.NewSession(
		&aws.Config{
			Credentials: credentials.NewStaticCredentials(
				*creds.AccessKeyId,
				*creds.SecretAccessKey,
				*creds.SessionToken,
			)})
	if err != nil {
		return sts.Credentials{}, err
	}

	client := sts.New(awsSession)

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
func (p *AWSSAMLProvider) roleSessionName() string {
	if name := p.Profiles[p.profile]["role_session_name"]; name != "" {
		return name
	}

	if p.defaultRoleSessionName != "" {
		return p.defaultRoleSessionName
	}

	// Try to work out a role name that will hopefully end up unique.
	return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
}

// GetRoleARN makes a call to AWS to get-caller-identity and returns the
// assumed role's name and ARN.
func GetRoleARN(c credentials.Value) (string, error) {
	awsSession, err := aws_session.NewSession(
		&aws.Config{
			Credentials: credentials.NewStaticCredentialsFromCreds(c),
		})
	if err != nil {
		return "", err
	}

	client := sts.New(awsSession)

	indentity, err := client.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Errorf("Error getting caller identity: %s", err.Error())
		return "", err
	}
	arn := *indentity.Arn
	return arn, nil
}

func selectRole(roleARN string, roles []AssumableRole) (int, error) {
	for roleIdx, role := range roles {
		if role.Role == roleARN {
			return roleIdx, nil
		}
	}
	// if we got to this point we didn't find a matching role, return an error.
	return -1, fmt.Errorf("invalid role arn passed in by configuration: %s", roleARN)
}

// Authenticates the user with AWS, if the auth process is successful a valid
// set of STS credentials are returned otherwise and error will be returned
// containing a message to explain the error.
func (p *AWSSAMLProvider) authenticateProfileWithRegion(profileARN string, duration time.Duration, oktaAWSSAMLURL string, region string) (sts.Credentials, error) {
	var assertion SAMLAssertion
	var roleIndex int
	queryParams := url.Values{}

	// Attempt to reuse session cookie
	err := p.getAWSSAML(oktaAWSSAMLURL, queryParams, nil, &assertion, "saml")
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")

		if err := p.oktaClient.AuthenticateUser(); err != nil {
			return sts.Credentials{}, err
		}

		queryParams.Set("onetimetoken", p.oktaClient.GetSessionToken())
		if err = p.getAWSSAML(oktaAWSSAMLURL, queryParams, nil, &assertion, "saml"); err != nil {
			return sts.Credentials{}, err
		}
	}
	roles, err := GetAssumableRolesFromSAML(assertion.Resp)
	if err != nil {
		return sts.Credentials{}, err
	}

	if profileARN != "" {
		roleIndex, err = selectRole(profileARN, roles)
		if err != nil {
			return sts.Credentials{}, fmt.Errorf("invalid role arn passed in by configuration: %s", profileARN)
		}
	} else {
		roleIndex, err := p.selector.ChooseRole(roles)
		if err != nil {
			return sts.Credentials{}, err
		}

		if roleIndex < 0 || roleIndex >= len(roles) {
			return sts.Credentials{}, fmt.Errorf("invalid index (%d) return by supplied `ChooseRole`. There are %d roles", roleIndex, len(roles))
		}
	}
	var samlSess *aws_session.Session
	if region != "" {
		log.Debugf("Using region: %s\n", region)
		conf := &aws.Config{
			Region: aws.String(region),
		}
		samlSess = aws_session.Must(aws_session.NewSession(conf))
	} else {
		samlSess = aws_session.Must(aws_session.NewSession())
	}
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(roles[roleIndex].Principal),
		RoleArn:         aws.String(roles[roleIndex].Role),
		SAMLAssertion:   aws.String(string(assertion.RawData)),
		DurationSeconds: aws.Int64(int64(duration.Seconds())),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", roles[roleIndex].Role).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, err
	}

	return *samlResp.Credentials, err
}

// Gets the AWS SAML assertion from OKTA.
//
// this includes parsing the HTML returned by Okta to retrieve the encoded SAML
// assertion passed via a hidden HTML element.
func (p *AWSSAMLProvider) getAWSSAML(path string, queryParams url.Values, data []byte, recv interface{}, format string) (err error) {
	res, err := p.oktaClient.Request("GET", path, queryParams, data, format, true)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", "GET", res.Request.URL, res.Status)
	} else if recv != nil {
		switch format {
		case "json":
			err = json.NewDecoder(res.Body).Decode(recv)
		default:
			var rawData []byte
			rawData, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return
			}
			if err := ParseSAML(rawData, recv.(*SAMLAssertion)); err != nil {
				log.Debug("SAML parsing failed: ", err)
				return fmt.Errorf("okta user does not have the AWS app added to their account, contact your Okta admin to make sure things are configured properly")
			}
		}
	}

	return
}

// get the full Okta SAML login url, including domain.
func (p *AWSSAMLProvider) GetSAMLLoginURL() (*url.URL, error) {
	return p.oktaClient.GetURL(p.oktaAWSSAMLURL)
}
