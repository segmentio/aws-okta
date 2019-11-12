// Client for making requests to Okta APIs
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/client/mfa"
	"github.com/segmentio/aws-okta/lib/client/types"
	log "github.com/sirupsen/logrus"
)

const (
	Timeout = time.Duration(60 * time.Second)
)

type OktaClientOptions struct {
	// user supplied http client. If passed in this will replace the default
	HTTPClient *http.Client
	// http client timeout. default 60s
	HTTPClientTimeout *time.Duration
}

type OktaClient struct {
	creds      OktaCredential
	userAuth   *types.OktaUserAuthn
	DuoClient  *lib.DuoClient
	BaseURL    *url.URL
	sessions   SessionCache
	client     http.Client
	selector   MFAInputs
	mfaDevices []mfa.Device
}

type MFAInputs interface {
	ChooseFactor(factors []mfa.Config) (int, error)
	CodeSupplier(factor mfa.Config) (string, error)
}

type SessionCache interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte, label string) error
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
func NewOktaClient(
	creds OktaCredential,
	sessions SessionCache,
	selector MFAInputs,
	opts *OktaClientOptions) (*OktaClient, error) {
	var client http.Client
	var err error

	// if nil opts is passed in, initialize an empty opts struct
	if opts == nil {
		opts = &OktaClientOptions{}
	}

	err = creds.Validate()
	if err != nil {
		return nil, err
	}

	// url parse & set base
	base, err := url.Parse(fmt.Sprintf(
		"https://%s", creds.Domain,
	))
	if err != nil {
		return nil, fmt.Errorf("%v %w", err, types.ErrInvalidCredentials)
	}

	// if an http client is passed in then use that instead of creating one.
	if opts.HTTPClient != nil {
		client = *opts.HTTPClient
	} else {
		jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		if err != nil {
			return nil, fmt.Errorf("%v %w", "Unable to create cookie jar", err)
		}

		transCfg := &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: Timeout,
		}

		// if a timeout is passed in then use that timeout.
		if opts.HTTPClientTimeout != nil {
			transCfg.TLSHandshakeTimeout = *opts.HTTPClientTimeout
		}

		client = http.Client{
			Transport: transCfg,
			Timeout:   Timeout,
			Jar:       jar,
		}
	}
	devices := mfa.DefaultDevices(selector)
	oktaClient := OktaClient{
		creds:      creds,
		BaseURL:    base,
		userAuth:   &types.OktaUserAuthn{},
		sessions:   sessions,
		client:     client,
		selector:   selector,
		mfaDevices: devices,
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
		return fmt.Errorf("session NOT retrieved. Reason: Session Backend not defined")
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
		return fmt.Errorf("session NOT saved. Reason: Session Backend not defined")
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
func (o *OktaClient) ValidateSession() error {
	var mySessionResponse *http.Response
	var err error

	log.Debug("Checking if we have a valid Okta session")
	mySessionResponse, err = o.Request("GET", "api/v1/sessions/me", url.Values{}, []byte{}, "json", false)
	if err != nil {
		return err
	}
	defer mySessionResponse.Body.Close()

	// https://developer.okta.com/docs/reference/api/sessions/#get-current-session
	// "if the session is invalid, a 404 Not Found response will be returned."
	// checking for ok status (200) is adequate to see if the session is still valid.
	if mySessionResponse.StatusCode == http.StatusNotFound {
		return fmt.Errorf("session is invalid. %w", types.ErrInvalidSession)
	} else if mySessionResponse.StatusCode == http.StatusOK {
		return nil
	} else {
		// we might want additional debug output for this case.
		return fmt.Errorf("unexpected status code: %d.%w", mySessionResponse.StatusCode, types.ErrUnexpectedResponse)
	}
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

	payload, err = json.Marshal(map[string]string{"username": o.creds.Username, "password": o.creds.Password})
	if err != nil {
		return
	}

	log.Debug("Posting first call to authenticate the user.")
	res, err := o.Request("POST", "api/v1/authn", url.Values{}, payload, "json", true)
	if err != nil {
		return err
		//fmt.Errorf("Failed to authenticate with okta. If your credentials have changed, use 'aws-okta add': %#v", err)
	}
	defer res.Body.Close()

	// validate we're getting a response code we can use.
	if res.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%v. %w", err, types.ErrInvalidCredentials)
	} else if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%v. %w", err, types.ErrUnexpectedResponse)
	}

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
		return fmt.Errorf("password is expired, login to Okta console to change. %w", types.ErrInvalidCredentials)
	}

	if o.userAuth.SessionToken == "" {
		log.Debug("Auth failed. Reason: Session token isn't present.")
		return fmt.Errorf("authentication failed for %s, session token not present. %w", o.creds.Username, types.ErrInvalidSession)
	}
	return
}

// Public interface to get the Okta session token.
func (o *OktaClient) GetSessionToken() string {
	return o.userAuth.SessionToken
}

// Will prompt the user to select one of the configured MFA devices if an MFA
// configuration isn't provided.
func (o *OktaClient) selectMFADevice() (mfa.Device, error) {
	var haveMFAConfig bool
	var availableDevices []mfa.Device
	var availableFactors []types.OktaUserAuthnFactor

	factors := o.userAuth.Embedded.Factors

	haveMFAConfig = o.creds.MFA.Provider != "" && o.creds.MFA.FactorType != ""

	for _, factor := range factors {
		supported := false
		var device mfa.Device
		for _, dev := range o.mfaDevices {
			log.Debug("checking factor: ", factor, " against device: ", dev)
			if dev.Supported(factor) == nil {
				supported = true
				device = dev
				break
			}
		}
		if supported {
			device.SetId(factor.Id)
			availableDevices = append(availableDevices, device)
			availableFactors = append(availableFactors, factor)
		}
	}
	// Okta has prompted us for MFA but the user doesn't have any MFA configure.
	// treat this as a credential error because the user doesn't have a full set
	// of credentials to auth.
	if len(availableFactors) == 0 {
		return nil, fmt.Errorf("no MFA devices registered but MFA Requested by Okta. %w", types.ErrInvalidCredentials)

		// if no MFA config is supplied and there is only one factor use that one.
	} else if len(availableFactors) == 1 && !haveMFAConfig {
		return availableDevices[0], nil
	}
	factorsI := make([]mfa.Config, len(availableFactors))
	for factorIndex, factor := range availableFactors {
		if haveMFAConfig {
			if strings.EqualFold(factor.Provider, o.creds.MFA.Provider) && strings.EqualFold(factor.FactorType, o.creds.MFA.FactorType) {
				// if the user passed in a specific MFA config to use that matches a
				// a factor we got from Okta then early exit and don't prompt them
				log.Debugf("Using matching factor \"%v %v\" from config\n", factor.Provider, factor.FactorType)
				return availableDevices[factorIndex], nil
			}
		}
		factorsI[factorIndex] = mfa.Config{
			Provider:   factor.Provider,
			FactorType: factor.FactorType,
			Id:         factor.Id}
	}

	// if we have MFA configured but it doesn't match what is returned by Okta.
	// return an error.
	if haveMFAConfig {
		return nil, fmt.Errorf("MFA Config doesn't match what is provided by Okta. %w", types.ErrInvalidCredentials)
	}

	// call out to the supplied ChooseFactor method to determine the factor.
	factorIdx, err := o.selector.ChooseFactor(factorsI)
	if err != nil {
		// this isn't one of our errors. return as is.
		return nil, err
	}

	// confirm the response we got from ChooseFactor is valid
	if factorIdx < 0 || factorIdx >= len(factors) {
		return nil, fmt.Errorf("invalid index (%d) return by supplied `ChooseFactor`. %w", factorIdx, types.ErrUnexpectedResponse)
	}
	return availableDevices[factorIdx], nil
}

// Makes any initial requests that are needed to verify MFA
//
// as an example this would include sending a request for an SMS code.
/*
func (o *OktaClient) preChallenge(mfaConfig mfa.Config) ([]byte, error) {
	var mfaCode string
	var err error

	//Software and Hardware based OTP Tokens
	if strings.Contains(mfaConfig.FactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = o.selector.CodeSupplier(mfaConfig)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(mfaConfig.FactorType, "sms") {
		log.Debug("SMS MFA")
		payload, err := json.Marshal(map[string]string{
			"stateToken": o.userAuth.StateToken,
		})
		if err != nil {
			return nil, err
		}

		log.Debug("Requesting SMS Code")
		res, err := o.Request("POST", "api/v1/authn/factors/"+mfaConfig.Id+"/verify", url.Values{}, payload, "json", true)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			errResp, err := parseOktaError(res)
			if err != nil {
				return nil, fmt.Errorf("received %d code from Okta for SMS MFA verify. %w", res.StatusCode, types.ErrUnexpectedResponse)
			}
			return nil, fmt.Errorf(
				"received %d code from Okta for SMS MFA verify.\nerrorCode: %s, errorSummary: %s\n%w",
				res.StatusCode,
				errResp.ErrorCode,
				errResp.ErrorSummary,
				types.ErrUnexpectedResponse)
		}
		mfaCode, err = o.selector.CodeSupplier(mfaConfig)
		if err != nil {
			return nil, err
		}
	}

	payload, err := json.Marshal(types.OktaStateToken{
		StateToken: o.userAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}
*/
// executes the second step (if required) of the MFA verifaction process to get
// a valid session cookie.
/*
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
					return fmt.Errorf("failed Duo challenge. Err: %s", duoErr)
				}
			default:
				res, err := o.Request("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify", url.Values{}, payload, "json", true)
				if err != nil {
					return fmt.Errorf("failed authn verification for okta. Err: %s", err)
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
*/
// helper function to get a url, including path, for an Okta api or app.
func (o *OktaClient) GetURL(path string) (fullURL *url.URL, err error) {

	fullURL, err = url.Parse(fmt.Sprintf(
		"%s/%s",
		o.BaseURL,
		path,
	))
	return
}

/*
func (o *OktaClient) validateFactor() (*mfa.Config, error) {
	var validationErrorMessage string
	factor, err := o.selectMFADevice()
	if err != nil {
		// error is set by selectMFADevice.
		return nil, err
	}
	if factor.Provider == "" {
		validationErrorMessage = "Provider for MFA Device unavailable.\n"
	}
	if factor.FactorType == "" {
		validationErrorMessage += "Factor type for MFA device unavailable.\n"
	}
	if factor.Id == "" {
		validationErrorMessage += "ID for MFA device unavailable.\n"
	}
	if validationErrorMessage != "" {
		return nil, fmt.Errorf("%v%w", validationErrorMessage, ErrInvalidCredentials)
	}

	mfaFactor := MFAConfig{
		Provider:   factor.Provider,
		Id:         factor.Id,
		FactorType: factor.FactorType}

	err = isFactorSupported(mfaFactor)
	if err != nil {
		return nil, err
	}

	log.Debugf("Okta Factor Provider: %s", factor.Provider)
	log.Debugf("Okta Factor ID: %s", factor.Id)
	log.Debugf("Okta Factor Type: %s", factor.FactorType)

	return &mfaFactor, nil
}
*/
func (o *OktaClient) challengeMFA() (err error) {
	var payload []byte
	//var mfaFactor mfa.Config
	//mfaDevice, err := o.validateFactor()
	mfaDevice, err := o.selectMFADevice()
	if err != nil {
		return
	}
	log.Debug("auth status: ", o.userAuth.Status)
	for o.userAuth.Status == "MFA_CHALLENGE" || o.userAuth.Status == "MFA_REQUIRED" {
		log.Debug("calling verify for device: ", mfaDevice)
		payload, err = mfaDevice.Verify(*o.userAuth)
		if err != nil {
			return
		}
		deviceId := mfaDevice.GetId()

		if deviceId == "" {
			log.Debug("MFA device is empty")
			return fmt.Errorf("registered MFA Device does not have an ID")
		}
		res, err := o.Request("POST", "api/v1/authn/factors/"+deviceId+"/verify", url.Values{}, payload, "json", true)
		if err != nil {
			return fmt.Errorf("failed authn verification for okta. Err: %s", err)
		}
		defer res.Body.Close()

		// we need to check statuscode here and handle errors.
		if res.StatusCode != http.StatusOK {
			// got an error response, try parsing it.
			errResp, err := parseOktaError(res)
			if err != nil {
				return fmt.Errorf("%v %w", err, types.ErrUnexpectedResponse)
			}
			if res.StatusCode == http.StatusForbidden {
				return fmt.Errorf("failed authn. Reason: %s. %w", errResp.ErrorSummary, types.ErrInvalidCredentials)
			} else {
				return fmt.Errorf(
					"failed authn verification. errorCode: %s, errorSummary: %s %w",
					errResp.ErrorCode,
					errResp.ErrorSummary,
					types.ErrUnexpectedResponse)
			}
		}
		err = json.NewDecoder(res.Body).Decode(&o.userAuth)
		if err != nil {
			return err
		}
	}
	//Handle Push Notification
	//	err = o.postChallenge(payload, mfaFactor.Provider, mfaFactor.Id)
	//	if err != nil {
	//		return err
	//	}
	return nil
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
