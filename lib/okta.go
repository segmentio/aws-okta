package lib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/segmentio/aws-okta/lib/mfa"
	"github.com/segmentio/aws-okta/lib/saml"
	log "github.com/sirupsen/logrus"
)

const (
	OktaServerUs      = "okta.com"
	OktaServerEmea    = "okta-emea.com"
	OktaServerPreview = "oktapreview.com"
	OktaServerDefault = OktaServerUs

	// deprecated; use OktaServerUs
	OktaServer = OktaServerUs

	Timeout = time.Duration(60 * time.Second)
)

type OktaClient struct {
	// Organization will be deprecated in the future
	Organization    string
	Username        string
	Password        string
	UserAuth        *OktaUserAuthn
	DuoClient       *DuoClient
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	OktaAwsSAMLUrl  string
	CookieJar       http.CookieJar
	BaseURL         *url.URL
	Domain          string
	MFAConfig       MFAConfig
}

type MFAConfig struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

type OktaCreds struct {
	// Organization will be deprecated in the future
	Organization string
	Username     string
	Password     string
	Domain       string
}

type OktaCookies struct {
	Session     string
	DeviceToken string
}

func (c *OktaCreds) Validate(mfaConfig MFAConfig) error {
	// OktaClient assumes we're doing some AWS SAML calls, but Validate doesn't
	var cookies OktaCookies

	o, err := NewOktaClient2(*c, "", cookies, mfaConfig)
	if err != nil {
		return err
	}

	if err := o.AuthenticateUser(); err != nil {
		return err
	}

	return nil
}

func GetOktaDomain(region string) (string, error) {
	switch region {
	case "us":
		return OktaServerUs, nil
	case "emea":
		return OktaServerEmea, nil
	case "preview":
		return OktaServerPreview, nil
	}
	return "", fmt.Errorf("invalid region %s", region)
}

func NewOktaClient(creds OktaCreds, oktaAwsSAMLUrl string, sessionCookie string, mfaConfig MFAConfig) (*OktaClient, error) {
	var cookies OktaCookies
	cookies.Session = sessionCookie

	return NewOktaClient2(creds, oktaAwsSAMLUrl, cookies, mfaConfig)
}

func NewOktaClient2(creds OktaCreds, oktaAwsSAMLUrl string, cookies OktaCookies, mfaConfig MFAConfig) (*OktaClient, error) {
	var domain string

	// maintain compatibility for deprecated creds.Organization
	if creds.Domain == "" && creds.Organization != "" {
		domain = fmt.Sprintf("%s.%s", creds.Organization, OktaServerDefault)
	} else if creds.Domain != "" {
		domain = creds.Domain
	} else {
		return &OktaClient{}, errors.New("either creds.Organization (deprecated) or creds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-okta add`")
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf(
		"https://%s", domain,
	))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	if cookies.Session != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:  "sid",
				Value: cookies.Session,
			},
		})
	}
	if cookies.DeviceToken != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:  "DT",
				Value: cookies.DeviceToken,
			},
		})
	}
	log.Debug("domain: " + domain)

	return &OktaClient{
		// Setting Organization for backwards compatibility
		Organization:   creds.Organization,
		Username:       creds.Username,
		Password:       creds.Password,
		OktaAwsSAMLUrl: oktaAwsSAMLUrl,
		CookieJar:      jar,
		BaseURL:        base,
		Domain:         domain,
		MFAConfig:      mfaConfig,
	}, nil
}

func (o *OktaClient) AuthenticateUser() error {
	var oktaUserAuthn OktaUserAuthn

	// Step 1 : Basic authentication

	user := OktaUser{
		Username: o.Username,
		Password: o.Password,
	}

	payload, err := json.Marshal(user)
	if err != nil {
		return err
	}

	log.Debug("Step: 1")
	err = o.Get("POST", "api/v1/authn", payload, &oktaUserAuthn, "json")
	if err != nil {
		return fmt.Errorf("Failed to authenticate with okta. If your credentials have changed, use 'aws-okta add': %#v", err)
	}

	o.UserAuth = &oktaUserAuthn

	// Step 2 : Challenge MFA if needed
	log.Debug("Step: 2")
	if o.UserAuth.Status == "MFA_REQUIRED" {
		log.Info("Requesting MFA. Please complete two-factor authentication with your second device")
		if err = o.challengeMFA(); err != nil {
			return err
		}
	}

	if o.UserAuth.SessionToken == "" {
		return fmt.Errorf("authentication failed for %s", o.Username)
	}

	return nil
}

func (o *OktaClient) AuthenticateProfile(profileARN string, duration time.Duration) (sts.Credentials, string, error) {
	return o.AuthenticateProfileWithRegion(profileARN, duration, "")
}

func (o *OktaClient) AuthenticateProfileWithRegion(profileARN string, duration time.Duration, region string) (sts.Credentials, string, error) {
	creds, cookies, err := o.AuthenticateProfile3(profileARN, duration, region)

	return creds, cookies.Session, err
}

func (o *OktaClient) AuthenticateProfile3(profileARN string, duration time.Duration, region string) (sts.Credentials, OktaCookies, error) {

	// Attempt to reuse session cookie
	var assertion SAMLAssertion
	var oc OktaCookies

	err := o.Get("GET", o.OktaAwsSAMLUrl, nil, &assertion, "saml")
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")

		// Clear DT cookie before starting AuthN flow again. Bug #279.
		o.CookieJar.SetCookies(o.BaseURL, []*http.Cookie{
			{
				Name:  "DT",
				MaxAge: -1,
			},
		})

		// Call again to get a new DT cookie and ignore the error
		err := o.Get("GET", o.OktaAwsSAMLUrl, nil, &assertion, "saml")

		if err := o.AuthenticateUser(); err != nil {
			return sts.Credentials{}, oc, err
		}

		// Step 3 : Get SAML Assertion and retrieve IAM Roles
		log.Debug("Step: 3")
		if err = o.Get("GET", o.OktaAwsSAMLUrl+"?onetimetoken="+o.UserAuth.SessionToken,
			nil, &assertion, "saml"); err != nil {
			return sts.Credentials{}, oc, err
		}
	}

	principal, role, err := GetRoleFromSAML(assertion.Resp, profileARN)
	if err != nil {
		return sts.Credentials{}, oc, err
	}

	// Step 4 : Assume Role with SAML
	log.Debug("Step 4: Assume Role with SAML")
	var samlSess *session.Session
	if region != "" {
		log.Debugf("Using region: %s\n", region)
		conf := &aws.Config{
			Region:              aws.String(region),
			STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
		}
		samlSess = session.Must(session.NewSession(conf))
	} else {
		samlSess = session.Must(session.NewSession())
	}
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(principal),
		RoleArn:         aws.String(role),
		SAMLAssertion:   aws.String(string(assertion.RawData)),
		DurationSeconds: aws.Int64(int64(duration.Seconds())),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", role).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, oc, err
	}

	cookies := o.CookieJar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			oc.Session = cookie.Value
		}
		if cookie.Name == "DT" {
			oc.DeviceToken = cookie.Value
		}
	}

	return *samlResp.Credentials, oc, nil
}

func selectMFADeviceFromConfig(o *OktaClient) (*OktaUserAuthnFactor, error) {
	log.Debugf("MFAConfig: %v\n", o.MFAConfig)
	if o.MFAConfig.Provider == "" || o.MFAConfig.FactorType == "" {
		return nil, nil
	}

	for _, f := range o.UserAuth.Embedded.Factors {
		log.Debugf("%v\n", f)
		if strings.EqualFold(f.Provider, o.MFAConfig.Provider) && strings.EqualFold(f.FactorType, o.MFAConfig.FactorType) {
			log.Debugf("Using matching factor \"%v %v\" from config\n", f.Provider, f.FactorType)
			return &f, nil
		}
	}

	return nil, fmt.Errorf("Failed to select MFA device with Provider = \"%s\", FactorType = \"%s\"", o.MFAConfig.Provider, o.MFAConfig.FactorType)
}

func (o *OktaClient) selectMFADevice() (*OktaUserAuthnFactor, error) {
	factors := o.UserAuth.Embedded.Factors
	if len(factors) == 0 {
		return nil, errors.New("No available MFA Factors")
	} else if len(factors) == 1 {
		return &factors[0], nil
	}

	factor, err := selectMFADeviceFromConfig(o)
	if err != nil {
		return nil, err
	}

	if factor != nil {
		return factor, nil
	}

	log.Info("Select a MFA from the following list")
	for i, f := range factors {
		log.Infof("%d: %s (%s)", i, f.Provider, f.FactorType)
	}
	i, err := Prompt("Select MFA method", false)
	if i == "" {
		return nil, errors.New("Invalid selection - Please use an option that is listed")
	}
	if err != nil {
		return nil, err
	}
	factorIdx, err := strconv.Atoi(i)
	if err != nil {
		return nil, err
	}
	if factorIdx > (len(factors) - 1) {
		return nil, errors.New("Invalid selection - Please use an option that is listed")
	}
	return &factors[factorIdx], nil
}

func (o *OktaClient) preChallenge(oktaFactorId, oktaFactorType string) ([]byte, error) {
	var mfaCode string
	var err error

	//Software and Hardware based OTP Tokens
	if strings.Contains(oktaFactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = Prompt("Enter MFA Code", false)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(oktaFactorType, "sms") {
		log.Debug("SMS MFA")
		payload, err := json.Marshal(OktaStateToken{
			StateToken: o.UserAuth.StateToken,
		})
		if err != nil {
			return nil, err
		}
		var sms interface{}
		log.Debug("Requesting SMS Code")
		err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
			payload, &sms, "json",
		)
		if err != nil {
			return nil, err
		}
		mfaCode, err = Prompt("Enter MFA Code from SMS", false)
		if err != nil {
			return nil, err
		}
	}

	payload, err := json.Marshal(OktaStateToken{
		StateToken: o.UserAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (o *OktaClient) postChallenge(payload []byte, oktaFactorProvider string, oktaFactorId string) error {
	//Initiate Push Notification
	if o.UserAuth.Status == "MFA_CHALLENGE" {
		f := o.UserAuth.Embedded.Factor
		errChan := make(chan error, 1)

		if oktaFactorProvider == "DUO" {
			// Contact the Duo to initiate Push notification
			if f.Embedded.Verification.Host != "" {
				o.DuoClient = &DuoClient{
					Host:       f.Embedded.Verification.Host,
					Signature:  f.Embedded.Verification.Signature,
					Callback:   f.Embedded.Verification.Links.Complete.Href,
					Device:     o.MFAConfig.DuoDevice,
					StateToken: o.UserAuth.StateToken,
				}

				log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
					f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
					o.UserAuth.StateToken)

				go func() {
					log.Debug("challenge u2f")
					log.Info("Sending Push Notification...")
					err := o.DuoClient.ChallengeU2f(f.Embedded.Verification.Host)
					if err != nil {
						errChan <- err
					}
				}()
			}
		} else if oktaFactorProvider == "FIDO" {
			f := o.UserAuth.Embedded.Factor

			log.Debug("FIDO WebAuthn Details:")
			log.Debug("  ChallengeNonce: ", f.Embedded.Challenge.Challenge)
			log.Debug("  AppId: ", o.Domain)
			log.Debug("  CredentialId: ", f.Profile.CredentialId)
			log.Debug("  StateToken: ", o.UserAuth.StateToken)

			fidoClient, err := mfa.NewFidoClient(f.Embedded.Challenge.Challenge,
				o.Domain,
				f.Profile.CredentialId,
				o.UserAuth.StateToken)
			if err != nil {
				return err
			}

			signedAssertion, err := fidoClient.ChallengeU2f()
			if err != nil {
				return err
			}
			// re-assign the payload to provide U2F responses.
			payload, err = json.Marshal(signedAssertion)
			if err != nil {
				return err
			}
		}
		// Poll Okta until authentication has been completed
		for o.UserAuth.Status != "SUCCESS" {
			select {
			case duoErr := <-errChan:
				log.Printf("Err: %s", duoErr)
				if duoErr != nil {
					return fmt.Errorf("Failed Duo challenge. Err: %s", duoErr)
				}
			default:
				err := o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
					payload, &o.UserAuth, "json",
				)
				if err != nil {
					return fmt.Errorf("Failed authn verification for okta. Err: %s", err)
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

func (o *OktaClient) challengeMFA() (err error) {
	var oktaFactorProvider string
	var oktaFactorId string
	var payload []byte
	var oktaFactorType string

	factor, err := o.selectMFADevice()
	if err != nil {
		log.Debug("Failed to select MFA device")
		return
	}
	oktaFactorProvider = factor.Provider
	if oktaFactorProvider == "" {
		return
	}
	oktaFactorId, err = GetFactorId(factor)
	if err != nil {
		return
	}
	oktaFactorType = factor.FactorType
	if oktaFactorId == "" {
		return
	}
	log.Debugf("Okta Factor Provider: %s", oktaFactorProvider)
	log.Debugf("Okta Factor ID: %s", oktaFactorId)
	log.Debugf("Okta Factor Type: %s", oktaFactorType)

	payload, err = o.preChallenge(oktaFactorId, oktaFactorType)

	err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify?rememberDevice=true",
		payload, &o.UserAuth, "json",
	)
	if err != nil {
		return
	}

	//Handle Push Notification
	err = o.postChallenge(payload, oktaFactorProvider, oktaFactorId)
	if err != nil {
		return err
	}
	return
}

func GetFactorId(f *OktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	case "token":
		if f.Provider == "SYMANTEC" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor token not supported", f.Provider)
		}
	case "token:software:totp":
		id = f.Id
	case "token:hardware":
		id = f.Id
	case "sms":
		id = f.Id
	case "u2f", "webauthn":
		id = f.Id
	case "push":
		if f.Provider == "OKTA" || f.Provider == "DUO" {
			id = f.Id
		} else {
			err = fmt.Errorf("provider %s with factor push not supported", f.Provider)
		}
	default:
		err = fmt.Errorf("factor %s not supported", f.FactorType)
	}
	return
}

func (o *OktaClient) Get(method string, path string, data []byte, recv interface{}, format string) (err error) {
	var res *http.Response
	var body []byte
	var header http.Header
	var client http.Client

	url, err := url.Parse(fmt.Sprintf(
		"%s/%s", o.BaseURL, path,
	))
	if err != nil {
		return err
	}

	if format == "json" {
		header = http.Header{
			"Accept":        []string{"application/json"},
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-cache"},
		}
	} else {
		// disable gzip encoding; it was causing spurious EOFs
		// for some users; see #148
		header = http.Header{
			"Accept-Encoding": []string{"identity"},
		}
	}

	transCfg := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: Timeout,
	}
	client = http.Client{
		Transport: transCfg,
		Timeout:   Timeout,
		Jar:       o.CookieJar,
	}

	req := &http.Request{
		Method:        method,
		URL:           url,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(body)),
	}

	if res, err = client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", method, url, res.Status)
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
				return fmt.Errorf("Okta user %s does not have the AWS app added to their account.  Please contact your Okta admin to make sure things are configured properly.", o.Username)
			}
		}
	}

	return
}

type OktaProvider struct {
	Keyring         keyring.Keyring
	ProfileARN      string
	SessionDuration time.Duration
	OktaAwsSAMLUrl  string
	// OktaSessionCookieKey represents the name of the session cookie
	// to be stored in the keyring.
	OktaSessionCookieKey string
	OktaAccountName      string
	MFAConfig            MFAConfig
	AwsRegion            string
}

func (p *OktaProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debugf("Using okta provider (%s)", p.OktaAccountName)
	item, err := p.Keyring.Get(p.OktaAccountName)
	if err == keyring.ErrKeyNotFound {
		return sts.Credentials{}, "", errors.New("Okta credentials are not in your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}
	if err != nil {
		log.Debugf("Couldnt get okta creds from keyring: %s", err)
		return sts.Credentials{}, "", err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return sts.Credentials{}, "", errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	// Check for stored session and device token cookies
	var cookies OktaCookies
	cookieItem, err := p.Keyring.Get(p.OktaSessionCookieKey)
	if err == nil {
		cookies.Session = string(cookieItem.Data)
	}
	cookieItem2, err := p.Keyring.Get("okta-device-token-cookie")
	if err == nil {
		cookies.DeviceToken = string(cookieItem2.Data)
	}

	oktaClient, err := NewOktaClient2(oktaCreds, p.OktaAwsSAMLUrl, cookies, p.MFAConfig)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	creds, newCookies, err := oktaClient.AuthenticateProfile3(p.ProfileARN, p.SessionDuration, p.AwsRegion)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	log.Debug("pOktaSessionCookieKey: ", p.OktaSessionCookieKey)

	newCookieItem := keyring.Item{
		Key:                         p.OktaSessionCookieKey,
		Data:                        []byte(newCookies.Session),
		Label:                       "okta session cookie",
		KeychainNotTrustApplication: false,
	}

	p.Keyring.Set(newCookieItem)

	newCookieItem2 := keyring.Item{
		Key:                         "okta-device-token-cookie",
		Data:                        []byte(newCookies.DeviceToken),
		Label:                       "okta device token",
		KeychainNotTrustApplication: false,
	}

	p.Keyring.Set(newCookieItem2)

	return creds, oktaCreds.Username, err
}

func (p *OktaProvider) GetSAMLLoginURL() (*url.URL, error) {
	item, err := p.Keyring.Get("okta-creds")
	if err != nil {
		log.Debugf("couldnt get okta creds from keyring: %s", err)
		return &url.URL{}, err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return &url.URL{}, errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	var samlURL string

	// maintain compatibility for deprecated creds.Organization
	if oktaCreds.Domain == "" && oktaCreds.Organization != "" {
		samlURL = fmt.Sprintf("%s.%s", oktaCreds.Organization, OktaServerDefault)
	} else if oktaCreds.Domain != "" {
		samlURL = oktaCreds.Domain
	} else {
		return &url.URL{}, errors.New("either oktaCreds.Organization (deprecated) or oktaCreds.Domain must be set, but not both. To remedy this, re-add your credentials with `aws-okta add`")
	}

	fullSamlURL, err := url.Parse(fmt.Sprintf(
		"https://%s/%s",
		samlURL,
		p.OktaAwsSAMLUrl,
	))

	if err != nil {
		return &url.URL{}, err
	}

	return fullSamlURL, nil
}
