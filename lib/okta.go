package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"
)

const (
	OktaServerUs      = "okta.com"
	OktaServerEmea    = "okta-emea.com"
	OktaServerPreview = "oktapreview.com"
	OktaServerDefault = OktaServerUs

	// deprecated; use OktaServerUs
	OktaServer = OktaServerUs
)

type OktaCreds struct {
	// Organization will be deprecated in the future
	Organization string
	Username     string
	Password     string
	Domain       string
}

func (c *OktaCreds) Validate(mfaConfig MFAConfig) error {
	// NewOktaSAMLClient assumes we're doing some AWS SAML calls, but Validate doesn't
	o, err := NewOktaSAMLClient(*c, "", "", mfaConfig)
	if err != nil {
		return err
	}

	if err := o.AuthenticateUser(); err != nil {
		return err
	}

	return nil
}

type OktaProvider struct {
	Keyring         keyring.Keyring
	ProfileARN      string
	SessionDuration time.Duration
	OktaAwsSAMLUrl  string
	// OktaSessionCookieKey represents the name of the session cookie
	// to be stored in the keyring.
	OktaSessionCookieKey string
	MFAConfig            MFAConfig
}

func (p *OktaProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debug("using okta provider")
	item, err := p.Keyring.Get("okta-creds")
	if err != nil {
		log.Debugf("couldnt get okta creds from keyring: %s", err)
		return sts.Credentials{}, "", err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return sts.Credentials{}, "", errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	// Check for stored session cookie
	var sessionCookie string
	cookieItem, err := p.Keyring.Get(p.OktaSessionCookieKey)
	if err == nil {
		sessionCookie = string(cookieItem.Data)
	}

	oktaClient, err := NewOktaSAMLClient(oktaCreds, p.OktaAwsSAMLUrl, sessionCookie, p.MFAConfig)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	creds, newSessionCookie, err := oktaClient.AuthenticateProfile(p.ProfileARN, p.SessionDuration)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	newCookieItem := keyring.Item{
		Key:                         p.OktaSessionCookieKey,
		Data:                        []byte(newSessionCookie),
		Label:                       "okta session cookie",
		KeychainNotTrustApplication: false,
	}

	p.Keyring.Set(newCookieItem)

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
