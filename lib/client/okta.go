// Client for making requests to Okta APIs
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	//"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/mfa"
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
	creds        OktaCredential
	userAuth     *oktaUserAuthn
	DuoClient    *lib.DuoClient
	SessionToken string
	Expiration   time.Time
	BaseURL      *url.URL
	sessions     SessionCache
	client       http.Client
	selector     MFAInputs
}

type MFAInputs interface {
	ChooseFactor(factors []MFAConfig) (int, error)
	CodeSupplier(factor MFAConfig) (string, error)
}

type SessionCache interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte, label string) error
}

// type: OktaCredential struct stores Okta credentials and domain information that will
// be used by OktaClient when making API calls to Okta
type OktaCredential struct {
	Username string
	Password string
	Domain   string
	MFA      MFAConfig
}

type MFAConfig struct {
	Provider   string // Which MFA provider to use when presented with an MFA challenge
	FactorType string // Which of the factor types of the MFA provider to use
	DuoDevice  string // Which DUO device to use for DUO MFA
	Id         string // the unique id for the MFA device provided by Okta
}

// Checks the validity of OktaCredential and should be called before
// using the credentials to make API calls.
//
// This public method will only validate that credentials exist, it will NOT
// validate them for correctness. To validate correctness an OktaClient must be
// used to make a request to Okta.
func (c *OktaCredential) IsValid() bool {
	return c.Username != "" && c.Password != "" && c.Domain != ""
}

// Creates and initializes an OktaClient. This is intended to provide a simple
// way to create a client that can make requests to the Okta APIs.
//
// As an example for how a client might be used:
// This client can then be passed to a provider that will manage auth
// for other platforms. Currently AWS SAML provider is supported to get STS
// credentials to get access to AWS services.
//
// Supported configuration options:
//       TODO: expand on configuration options and add tests.
//
// -- proxy config: TBD
// -- session caching: Passing in a keyring will enable support for caching.
//      this will cache a valid okta session securely in the keyring. This
//			session is only for access to the Okta APIs, any additional sessions
//			(for example, aws STS credentials) will be cached by the provider that
//      creates them.
func NewOktaClient(creds OktaCredential, sessions SessionCache, selector MFAInputs) (*OktaClient, error) {

	if creds.IsValid() {
		log.Debug("Credentials are valid :", creds.Username, " @ ", creds.Domain)
	} else {
		return nil, errors.New("credentials aren't complete. To remedy this, re-add your credentials with `aws-okta add`")
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf(
		"https://%s", creds.Domain,
	))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	transCfg := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: Timeout,
	}

	client := http.Client{
		Transport: transCfg,
		Timeout:   Timeout,
		Jar:       jar,
	}

	oktaClient := OktaClient{
		creds:    creds,
		BaseURL:  base,
		userAuth: &oktaUserAuthn{},
		sessions: sessions,
		client:   client,
		selector: selector,
	}

	// this can fail if we don't have have a backend defined.
	// failing to retrived a cached cookie shouldn't fail the entire
	// operation. Let's check if we have the session caching functionality passed
	// in before trying to retrieve the session cookie.
	if oktaClient.sessions != nil {
		err = oktaClient.retrieveSessionCookie()
		if err != nil {
			// if there is no saved session we will get an error, we still want to create the OktaClient.
			log.Debug("Unable to retrieve session, got err: ", err)
		}
	}
	return &oktaClient, nil
}

// Gets the Okta session cookie and stores it in the cookie jar used by the
// http client which is used as the primary authentication mechanism.
//
// If a keyring isn't provided to the client then an error will be returned.
// This error indicates that the session wasn't retrieved and should be handled
// appropriately.
func (o *OktaClient) retrieveSessionCookie() (err error) {

	if o.sessions == nil {
		return fmt.Errorf("Session NOT retrieved. Reason: Session Backend not defined")
	}
	cookieItemData, err := (o.sessions).Get(o.getSessionCookieKeyringKey())
	if err == nil {
		o.client.Jar.SetCookies(o.BaseURL, []*http.Cookie{
			{
				Name:  "sid",
				Value: string(cookieItemData),
			},
		})
		log.Debug("Using Okta session: ", string(cookieItemData))
	}

	return
}

// returns the sesion key that is username and domain aware.
func (o *OktaClient) getSessionCookieKeyringKey() string {
	return "okta-session-cookie-" + o.creds.Username + "-" + o.creds.Domain
}

// Takes a session cookie in the cookie jar and saves it in the keychain,
// this allows it to be used across invocations where the client making the
// request is destroyed/created between requests.
func (o *OktaClient) saveSessionCookie() (err error) {

	if o.sessions == nil {
		return fmt.Errorf("Session NOT saved. Reason: Session Backend not defined")
	}
	cookies := o.client.Jar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" && cookie.Value != "" {
			err = (o.sessions).Put(o.getSessionCookieKeyringKey(),
				[]byte(cookie.Value),
				"okta session cookie for "+o.creds.Username)
			if err != nil {
				return
			}
			log.Debug("Saving Okta Session Cookie: ", cookie.Value)
		}
	}
	return
}

// Sends a request to the Okta Sessions API to validate if the session cookie
// is valid or not. This doesn't always mean that the session can be used for
// all Okta applications but it does accurately fetch the state of the session.
func (o *OktaClient) ValidateSession() (sessionValid bool, err error) {
	var mySessionResponse *http.Response
	sessionValid = false

	log.Debug("Checking if we have a valid Okta session")
	mySessionResponse, err = o.Request("GET", "api/v1/sessions/me", url.Values{}, []byte{}, "json", false)
	if err != nil {
		return
	}
	defer mySessionResponse.Body.Close()

	// https://developer.okta.com/docs/reference/api/sessions/#get-current-session
	// "if the session is invalid, a 404 Not Found response will be returned."
	// checking for ok status (200) is adequate to see if the session is still valid.
	sessionValid = mySessionResponse.StatusCode == http.StatusOK

	return
}

// Will authenticate a user and create a new session. Depending on how the Okta
// domain is configured MFA may be requested. Authentication flow supports
// several different MFA types including:
//
// SMS: Okta will send an SMS to the user that includes a code that needs to be
//      sent back as the verify step.
// PUSH: Either OKTA verify or DUO are supported.
// U2F: a u2f hardware token, eg. Yubikey
//
// TODO: document full list of MFA supported and create tests
//
// More details about the auth flow implemented by this client can be found in
// Okta documentation: https://developer.okta.com/docs/reference/api/authn
//
func (o *OktaClient) AuthenticateUser() (err error) {
	var payload []byte

	payload, err = json.Marshal(oktaUser{Username: o.creds.Username, Password: o.creds.Password})
	if err != nil {
		return
	}

	log.Debug("Posting first call to authenticate the user.")
	res, err := o.Request("POST", "api/v1/authn", url.Values{}, payload, "json", true)
	if err != nil {
		return fmt.Errorf("Failed to authenticate with okta. If your credentials have changed, use 'aws-okta add': %#v", err)
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&o.userAuth)
	if err != nil {
		return
	}
	// Step 2 : Challenge MFA if needed
	if o.userAuth.Status == "MFA_REQUIRED" {
		log.Info("Requesting MFA. Please complete two-factor authentication with your second device")
		if err = o.challengeMFA(); err != nil {
			return
		}
	} else if o.userAuth.Status == "PASSWORD_EXPIRED" {
		return fmt.Errorf("Password is expired, login to Okta console to change")
	}

	if o.userAuth.SessionToken == "" {
		log.Debug("Auth failed. Reason: Session token isn't present.")
		return fmt.Errorf("authentication failed for %s", o.creds.Username)
	}
	return
}

// Public interface to get the Okta session token.
func (o *OktaClient) GetSessionToken() string {
	return o.userAuth.SessionToken
}

// Will prompt the user to select one of the configured MFA devices if an MFA
// configuration isn't provided.
func (o *OktaClient) selectMFADevice() (*oktaUserAuthnFactor, error) {
	factors := o.userAuth.Embedded.Factors
	if len(factors) == 0 {
		return nil, errors.New("No available MFA Factors")
	} else if len(factors) == 1 {
		return &factors[0], nil
	}
	factorsI := make([]MFAConfig, len(factors))
	for factorIndex, factor := range factors {
		if o.creds.MFA.Provider != "" && o.creds.MFA.FactorType != "" {
			if strings.EqualFold(factor.Provider, o.creds.MFA.Provider) && strings.EqualFold(factor.FactorType, o.creds.MFA.FactorType) {
				// if the user passed in a specific MFA config to use that matches a
				// a factor we got from Okta then early exit and don't prompt them
				log.Debugf("Using matching factor \"%v %v\" from config\n", factor.Provider, factor.FactorType)
				return &factor, nil
			}
		}
		factorsI[factorIndex] = MFAConfig{
			Provider:   factor.Provider,
			FactorType: factor.FactorType,
			Id:         factor.Id}
	}

	factorIdx, err := o.selector.ChooseFactor(factorsI)
	if err != nil {
		return nil, err
	}
	return &factors[factorIdx], nil
}

// Makes any initial requests that are needed to verify MFA
//
// as an example this would include sending a request for an SMS code.
func (o *OktaClient) preChallenge(oktaFactorId, oktaFactorType string) ([]byte, error) {
	var mfaCode string
	var err error
	mfaConfig := MFAConfig{
		FactorType: oktaFactorType,
		Provider:   oktaFactorId}

	//Software and Hardware based OTP Tokens
	if strings.Contains(oktaFactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = o.selector.CodeSupplier(mfaConfig)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(oktaFactorType, "sms") {
		log.Debug("SMS MFA")
		payload, err := json.Marshal(oktaStateToken{
			StateToken: o.userAuth.StateToken,
		})
		if err != nil {
			return nil, err
		}
		log.Debug("Requesting SMS Code")
		res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		mfaCode, err = o.selector.CodeSupplier(mfaConfig)
		if err != nil {
			return nil, err
		}
	}

	payload, err := json.Marshal(oktaStateToken{
		StateToken: o.userAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// executes the second step (if required) of the MFA verifaction process to get
// a valid session cookie.
func (o *OktaClient) postChallenge(payload []byte, oktaFactorProvider string, oktaFactorId string) error {
	//Initiate Push Notification
	if o.userAuth.Status == "MFA_CHALLENGE" {
		f := o.userAuth.Embedded.Factor
		errChan := make(chan error, 1)

		if oktaFactorProvider == "DUO" {
			// Contact the Duo to initiate Push notification
			if f.Embedded.Verification.Host != "" {
				o.DuoClient = &lib.DuoClient{
					Host:       f.Embedded.Verification.Host,
					Signature:  f.Embedded.Verification.Signature,
					Callback:   f.Embedded.Verification.Links.Complete.Href,
					Device:     o.creds.MFA.DuoDevice,
					StateToken: o.userAuth.StateToken,
				}

				log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
					f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
					o.userAuth.StateToken)

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
			f := o.userAuth.Embedded.Factor

			log.Debug("FIDO U2F Details:")
			log.Debug("  ChallengeNonce: ", f.Embedded.Challenge.Nonce)
			log.Debug("  AppId: ", f.Profile.AppId)
			log.Debug("  CredentialId: ", f.Profile.CredentialId)
			log.Debug("  StateToken: ", o.userAuth.StateToken)

			fidoClient, err := mfa.NewFidoClient(f.Embedded.Challenge.Nonce,
				f.Profile.AppId,
				f.Profile.Version,
				f.Profile.CredentialId,
				o.userAuth.StateToken)
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
		for o.userAuth.Status != "SUCCESS" {
			select {
			case duoErr := <-errChan:
				log.Printf("Err: %s", duoErr)
				if duoErr != nil {
					return fmt.Errorf("Failed Duo challenge. Err: %s", duoErr)
				}
			default:
				res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
				if err != nil {
					return fmt.Errorf("Failed authn verification for okta. Err: %s", err)
				}
				defer res.Body.Close()

				err = json.NewDecoder(res.Body).Decode(&o.userAuth)
				if err != nil {
					return err
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

// helper function to get a url, including path, for an Okta api or app.
func (o *OktaClient) GetURL(path string) (fullURL *url.URL, err error) {

	fullURL, err = url.Parse(fmt.Sprintf(
		"%s/%s",
		o.BaseURL,
		path,
	))
	return
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
	oktaFactorId, err = getFactorId(factor)
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

	res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
	if err != nil {
		return fmt.Errorf("Failed authn verification for okta. Err: %s", err)
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&o.userAuth)
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

// Makes a request to Okta.
//
// Supports Core okta APIs or Okta apps that extend the Okta functionaliy.
//
// Options:
// -- method. the http method to use.
// -- path. the url path to use.
// -- queryParams. the query parameters to use in the request.
// -- data. the data that will be sent as part of the request body.
// -- format. use to set the encoding format header.
// -- followRedirects. will change the http client configuration to follow
//                     redirects or not.
//
// TODO: refactor this method signature to clarify the interface.
// something like:
// -- method.
// -- url.URL (including RawParams).
// -- requestBody.
// -- clientOptions. this would include things like encoding and follow redirects
func (o *OktaClient) Request(method string, path string, queryParams url.Values, data []byte, format string, followRedirects bool) (res *http.Response, err error) {
	var header http.Header

	requestUrl, err := url.Parse(fmt.Sprintf(
		"%s/%s", o.BaseURL, path,
	))
	if err != nil {
		return
	}
	requestUrl.RawQuery = queryParams.Encode()

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

	var checkRedirectFunc func(req *http.Request, via []*http.Request) error
	if !followRedirects {
		checkRedirectFunc = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	o.client.CheckRedirect = checkRedirectFunc

	req := &http.Request{
		Method:        method,
		URL:           requestUrl,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
	log.Debug(method, " ", requestUrl.String())

	res, err = o.client.Do(req)

	if o.sessions != nil {
		err = o.saveSessionCookie()
	}
	return
}
