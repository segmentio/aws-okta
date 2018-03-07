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
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/segmentio/aws-okta/lib/saml"
)

const (
	OktaServer = "okta.com"
)

type OktaClient struct {
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
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

type OktaCreds struct {
	Organization string
	Username     string
	Password     string
}

func NewOktaClient(creds OktaCreds, oktaAwsSAMLUrl string, sessionCookie string) (*OktaClient, error) {
	base, err := url.Parse(fmt.Sprintf(
		"https://%s.%s", creds.Organization, OktaServer,
	))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	if sessionCookie != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:  "sid",
				Value: sessionCookie,
			},
		})
	}

	return &OktaClient{
		Organization:   creds.Organization,
		Username:       creds.Username,
		Password:       creds.Password,
		OktaAwsSAMLUrl: oktaAwsSAMLUrl,
		CookieJar:      jar,
		BaseURL:        base,
	}, nil
}

func (o *OktaClient) AuthenticateProfile(profileARN string, duration time.Duration) (sts.Credentials, string, error) {
	var oktaUserAuthn OktaUserAuthn

	// Attempt to reuse session cookie
	var assertion SAMLAssertion
	err := o.Get("GET", o.OktaAwsSAMLUrl, nil, &assertion, "saml")
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")
		// Step 1 : Basic authentication
		user := OktaUser{
			Username: o.Username,
			Password: o.Password,
		}

		payload, err := json.Marshal(user)
		if err != nil {
			return sts.Credentials{}, "", err
		}

		log.Debug("Step: 1")
		err = o.Get("POST", "api/v1/authn", payload, &oktaUserAuthn, "json")
		if err != nil {
			return sts.Credentials{}, "", errors.New("Failed to authenticate with okta.  Please check that your credentials have been set correctly with `aws-okta add`")
		}

		o.UserAuth = &oktaUserAuthn

		// Step 2 : Challenge MFA if needed
		log.Debug("Step: 2")
		if o.UserAuth.Status == "MFA_REQUIRED" {
			log.Info("Sending push notification...")
			if err = o.challengeMFA(); err != nil {
				return sts.Credentials{}, "", err
			}
		}

		if o.UserAuth.SessionToken == "" {
			return sts.Credentials{}, "", fmt.Errorf("authentication failed for %s", o.Username)
		}

		// Step 3 : Get SAML Assertion and retrieve IAM Roles
		log.Debug("Step: 3")
		if err = o.Get("GET", o.OktaAwsSAMLUrl+"?onetimetoken="+o.UserAuth.SessionToken,
			nil, &assertion, "saml"); err != nil {
			return sts.Credentials{}, "", err
		}
	}

	principal, role, err := GetRoleFromSAML(assertion.Resp, profileARN)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	// Step 4 : Assume Role with SAML
	samlSess := session.Must(session.NewSession())
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
		return sts.Credentials{}, "", err
	}

	var sessionCookie string
	cookies := o.CookieJar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			sessionCookie = cookie.Value
		}
	}

	return *samlResp.Credentials, sessionCookie, nil
}

func (o *OktaClient) challengeMFA() (err error) {
	var oktaFactorId string
	var payload []byte
	var oktaFactorType string

	if len(o.UserAuth.Embedded.Factors) > 1 {
		log.Infof("Select a 2FA from the following list\n")
		for i, f := range o.UserAuth.Embedded.Factors {
			oktaFactorId, err = GetFactorId(&f)
			log.Infof("%d: %s\n", i, f.Provider)
		}
		i, err := Prompt("Select 2FA method", false)
		if err != nil {
			return err
		}
		factor, err := strconv.Atoi(i)
		if err != nil {
			return err
		}
		oktaFactorId, err = GetFactorId(&o.UserAuth.Embedded.Factors[factor])
		oktaFactorType = o.UserAuth.Embedded.Factors[factor].FactorType
		if err != nil {
			return err
		}
	} else {
		if o.UserAuth.Embedded.Factors[0] != nil {
			oktaFactorId, err = GetFactorId(&o.UserAuth.Embedded.Factors[0])
			oktaFactorType = o.UserAuth.Embedded.Factors[0].FactorType
		}
	}
	if oktaFactorId == "" {
		return
	}
	log.Debugf("Okta Factor ID: %s\n", oktaFactorId)
	log.Debugf("Okta Factor Type: %s\n", oktaFactorType)

	var mfaCode string
	if strings.Contains(oktaFactorType, "token") {
		mfaCode, err = Prompt("Enter 2FA Code", false)
		if err != nil {
			return
		}
	}

	payload, err = json.Marshal(OktaStateToken{
		StateToken: o.UserAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return
	}

	err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
		payload, &o.UserAuth, "json",
	)
	if err != nil {
		return
	}

	if o.UserAuth.Status == "MFA_CHALLENGE" {
		f := o.UserAuth.Embedded.Factor

		o.DuoClient = &DuoClient{
			Host:       f.Embedded.Verification.Host,
			Signature:  f.Embedded.Verification.Signature,
			Callback:   f.Embedded.Verification.Links.Complete.Href,
			StateToken: o.UserAuth.StateToken,
		}

		log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
			f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
			o.UserAuth.StateToken)

		errChan := make(chan error, 1)
		go func() {
			log.Debug("challenge u2f")
			err := o.DuoClient.ChallengeU2f()
			if err != nil {
				errChan <- err
			}
		}()

		// Poll Okta until Duo authentication has been completed
		for o.UserAuth.Status != "SUCCESS" {
			select {
			case duoErr := <-errChan:
				if duoErr != nil {
					return errors.New("Failed Duo challenge")
				}
			default:
				err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
					payload, &o.UserAuth, "json",
				)
				if err != nil {
					return err
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
	return
}

func GetFactorId(f *OktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	case "token:software:totp":
		id = f.Id
	case "token:hardware":
		id = f.Id
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
		"https://%s.%s/%s", o.Organization, OktaServer, path,
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
		header = http.Header{}
	}

	client = http.Client{
		Jar: o.CookieJar,
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
}

func (p *OktaProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debug("using okta provider")
	item, err := p.Keyring.Get("okta-creds")
	if err != nil {
		log.Debug("couldnt get okta creds from keyring: %s", err)
		return sts.Credentials{}, "", err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return sts.Credentials{}, "", errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	// Check for stored session cookie
	var sessionCookie string
	cookieItem, err := p.Keyring.Get("okta-session-cookie")
	if err == nil {
		sessionCookie = string(cookieItem.Data)
	}

	oktaClient, err := NewOktaClient(oktaCreds, p.OktaAwsSAMLUrl, sessionCookie)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	creds, newSessionCookie, err := oktaClient.AuthenticateProfile(p.ProfileARN, p.SessionDuration)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	newCookieItem := keyring.Item{
		Key:   "okta-session-cookie",
		Data:  []byte(newSessionCookie),
		Label: "okta session cookie",
		KeychainNotTrustApplication: false,
	}

	p.Keyring.Set(newCookieItem)

	return creds, oktaCreds.Username, err
}
