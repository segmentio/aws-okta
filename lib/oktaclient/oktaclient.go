package oktaclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	// "net/url"

	"github.com/segmentio/aws-okta/lib/v2/oktaclient/internal/marshal"
	"github.com/segmentio/aws-okta/lib/v2/oktaclient/internal/mfa"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

type Creds struct {
	Username string
	Password string
	Domain   string
}

// Client methods (besides ReAuth()) will automatically auth if necessary
type Client struct {
	Creds Creds

	sessionToken string
	// TODO: sessioncache

	// TODO: custom HTTP client?
	// client is initialized before first auth
	client *http.Client
}

func (c *Client) initHTTPClient() error {
	if c.client != nil {
		return nil
	}

	// needed for the Okta session cookie https://developer.okta.com/docs/reference/api/sessions/#session-cookie
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return fmt.Errorf("creating cookie jar: %w", err)
	}

	transCfg := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		/* TODO?
		TLSHandshakeTimeout: Timeout,
		*/
	}

	/* TODO?
	// if a timeout is passed in then use that timeout.
	if opts.HTTPClientTimeout != nil {
		transCfg.TLSHandshakeTimeout = *opts.HTTPClientTimeout
	}
	*/

	client := http.Client{
		Transport: transCfg,
		/* TODO?
		Timeout:   Timeout,
		*/
		Jar: jar,
	}
	c.client = &client
	return nil
}

func (c *Client) AuthenticateCreds() error {
	return c.ReAuth()
}

// TODO; is stub
type mfaInputs struct{}

/* TODO
func (m mfaInputs) ChooseFactor(factors []oldclientmfa.Config) (int, error) {
	log.Infof("got MFA factors: %v; choosing 0", factors)
	return 0, nil
}
*/

func (m mfaInputs) CodeSupplier(factorType string) (string, error) {
	return "", nil
}

type ErrHTTP struct {
	StatusCode int
	Method     string
	Path       string
}

func (e *ErrHTTP) Error() string {
	return http.StatusText(e.StatusCode)
}

var ErrPasswordExpired = errors.New("password expired")
var ErrEmptySessionToken = errors.New("empty session token")

func (c *Client) ReAuth() error {
	c.sessionToken = ""
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return fmt.Errorf("creating cookie jar: %w", err)
	}

	if err := c.initHTTPClient(); err != nil {
		return fmt.Errorf("initializing HTTP client: %w", err)
	}
	c.client.Jar = jar
	return c.DoAuth()
}

func (c *Client) DoAuth() error {
	// optimistically assume this session token is still valid
	if c.sessionToken != "" {
		return nil
	}

	if err := c.initHTTPClient(); err != nil {
		return fmt.Errorf("initializing HTTP client: %w", err)
	}

	body, err := json.Marshal(map[string]string{"username": c.Creds.Username, "password": c.Creds.Password})
	log.Debug("initial auth POST to api/v1/authn")
	res, err := c.client.Post(c.fullURL("api/v1/authn"), "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("POST to api/v1/authn: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return &ErrHTTP{StatusCode: res.StatusCode, Method: "POST", Path: "api/v1/authn"}
	}

	var userAuthn marshal.UserAuthn
	if err := json.NewDecoder(res.Body).Decode(&userAuthn); err != nil {
		return fmt.Errorf("decoding api/v1/authn response: %w")
	}

	if userAuthn.Status == marshal.UserAuthnStatusPasswordExpired {
		return ErrPasswordExpired
	}

	if userAuthn.Status == marshal.UserAuthnStatusMFARequired {
		log.Info("requesting MFA")
		if err = c.doMFA(&userAuthn); err != nil {
			return fmt.Errorf("challenging MFA: %w", err)
		}
	}

	if userAuthn.SessionToken == "" {
		return ErrEmptySessionToken
	}

	// TODO: we might need to save more
	c.sessionToken = userAuthn.SessionToken
	return nil
}

type ErrOktaErrorResponse struct {
	marshal.ErrorResponse
}

func (e *ErrOktaErrorResponse) Error() string {
	return fmt.Sprintf("code=%s id=%s summary=%s", e.ErrorCode, e.ErrorId, e.ErrorSummary)
}

// returns factor action path (or "" if unknown action)
func buildMFAPath(factorId string, action string) string {
	path := "api/v1/authn/factors/"

	switch action {
	case "verify":
		path += factorId + "/" + action
	case "cancel":
		path += action
	case "verify/resend":
		path += factorId + action
	default:
		return ""
	}
	return path
}

// TODO: maybe this whole thing belongs in mfa.Device*? As an embed
func (c *Client) doMFA(userAuthn *marshal.UserAuthn) error {
	// TODO: this probably needs an escape hatch (context?)
	// TODO: this should just copy in and use what it needs

	// TODO: selectMFADevice
	mfaDevices := []mfaDevice{
		&mfa.DUODevice{
			DeviceName: "phone1",
		},
	}
	mfaDevId, mfaDev, err := selectMFADevice(mfaDevices, *userAuthn)
	if err != nil {
		return fmt.Errorf("selecting MFA device: %w", err)
	}

	for userAuthn.Status == marshal.UserAuthnStatusMFAChallenge || userAuthn.Status == marshal.UserAuthnStatusMFARequired {
		log.Debugf("UserAuthn.Status %s; verifying MFA device %v", userAuthn.Status, mfaDev)
		action, payload, err := mfaDev.Verify(*userAuthn)
		if err != nil {
			return fmt.Errorf("verifying MFA device: %w", err)
		}

		path := buildMFAPath(mfaDevId, action)
		if path == "" {
			return fmt.Errorf("building MFA path from id %s with action %s", mfaDevId, action)
		}

		payloadj, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshalling payload: %w", err)
		}

		// POST to MFA path
		res, err := c.client.Post(c.fullURL(path), "application/json", bytes.NewBuffer(payloadj))
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			var errResp = marshal.ErrorResponse{}
			err := json.NewDecoder(res.Body).Decode(&errResp)
			if err != nil {
				return fmt.Errorf("parsing okta error from MFA POST: %w", err)
			}
			return fmt.Errorf("decoding error response from MFA POST %s; status %d: %w", path, res.StatusCode,
				&ErrOktaErrorResponse{ErrorResponse: errResp})
		}
		if err = json.NewDecoder(res.Body).Decode(&userAuthn); err != nil {
			return fmt.Errorf("parsing body from MFA POST %s: %w", path, err)
		}
	}

	return nil
}

type ErrNoMatchingMFADevices struct{}

func (e *ErrNoMatchingMFADevices) Error() string {
	return "no matching MFA devices"
}

// TODO: better name?

func selectMFADevice(devices []mfaDevice, userAuthn marshal.UserAuthn) (id string, selected mfaDevice, err error) {
	// TODO overhaul
	/* TODO
	haveMFAConfig := o.creds.MFA.Provider != "" && o.creds.MFA.FactorType != ""
	*/
	factors := userAuthn.Embedded.Factors

	// TODO: filter?
	type supportedMFADevice struct {
		id     string
		device mfaDevice
	}
	supported := []supportedMFADevice{}

	// filter out all factors that arent support by the client
	for _, f := range factors {
		// TODO: in fact, I think this just finds the first supported one
		for _, d := range devices {
			lctx := log.WithFields(log.Fields{
				"factorType":     f.FactorType,
				"factorProvider": f.Provider,
				"device":         d,
			})
			if d.Supports(f.FactorType, f.Provider) {
				lctx.Debug("supported")
				supported = append(supported, supportedMFADevice{
					id:     f.Id,
					device: d,
				})
				break
			} else {
				lctx.Debug("unsupported")
			}
		}
	}

	if len(supported) == 0 {
		return "", nil, &ErrNoMatchingMFADevices{}
	}
	if len(supported) == 1 {
		log.Debugf("only one MFA device applies: %v", supported[0])
		return supported[0].id, supported[0].device, nil
	}

	/* TODO
	// call out to the supplied ChooseFactor method to determine the factor.
	deviceIndex, err := o.selector.ChooseFactor(devices)
	if err != nil {
		// this isn't one of our errors. return as is.
		return mfa.Config{}, err
	}

	// confirm the response we got from ChooseFactor is valid
	if deviceIndex < 0 || deviceIndex >= len(devices) {
		return mfa.Config{}, fmt.Errorf("invalid index (%d) return by supplied `ChooseFactor`. %w", deviceIndex, types.ErrUnexpectedResponse)
	}
	*/
	return supported[0].id, supported[0].device, nil
}

type ErrInvalidAuthState struct {
	expected bool
	actual   bool
}

func (e *ErrInvalidAuthState) Error() string {
	return fmt.Sprintf("invalid auth state %s; expected %s", e.actual, e.expected)
}

func (c *Client) baseURL() string {
	// might allow customizing baseurl later
	return fmt.Sprintf("https://%s", c.Creds.Domain)
}

func (c *Client) fullURL(path string) string {
	return fmt.Sprintf("%s/%s", c.baseURL(), path)
}

func (c *Client) fullURLWithToken(path string) (*url.URL, error) {
	// add sessiontoken as onetimetoken if not already set
	url_, err := url.Parse(c.fullURL(path))
	if err != nil {
		return nil, fmt.Errorf("parsing path: %w", err)
	}
	q, err := url.ParseQuery(url_.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("parsing query: %w", err)
	}
	if _, ok := q["onetimetoken"]; !ok {
		q["onetimetoken"] = []string{c.sessionToken}
		url_.RawQuery = q.Encode()
	}
	return url_, nil
}

// Get is analogous to http.Client#Get, but handles auth
func (c *Client) Get(path string) (*http.Response, error) {
	// DoAuth implies initHTTPClient
	if err := c.DoAuth(); err != nil {
		return nil, err
	}

	fullURLWithToken, err := c.fullURLWithToken(path)
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}
	log.Tracef("GET %s", fullURLWithToken)
	return c.client.Get(fullURLWithToken.String())
}

// Do is analogous to http.Client#Do, but handles auth
// req.URL should reference a path relative to c.baseURL
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// DoAuth implies initHTTPClient
	if err := c.DoAuth(); err != nil {
		return nil, err
	}

	fullURLWithToken, err := c.fullURLWithToken(req.URL.RequestURI())
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}
	req2 := *req
	req2.URL = fullURLWithToken
	log.Tracef("Do %s %s", req2.Method, req2.URL)
	return c.client.Do(&req2)
}
