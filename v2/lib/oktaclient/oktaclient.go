package oktaclient

import (
	"fmt"
	"net/http"
	"net/url"

	oldclient "github.com/segmentio/aws-okta/lib/client"
	"github.com/segmentio/aws-okta/lib/client/mfa"
	oldclientmfa "github.com/segmentio/aws-okta/lib/client/mfa"
	log "github.com/sirupsen/logrus"
)

type Creds struct {
	Username string
	Password string
	Domain   string
}

type Client struct {
	// TODO: temp: this needs pulling into v2
	oldClient *oldclient.OktaClient
	Creds     Creds

	// if true, Get will skip DoAuth
	Authed bool
	// TODO: sessioncache

	// TODO: custom HTTP client?
}

func (c *Client) AuthenticateCreds() error {
	c.Authed = false
	return c.DoAuth()
}

// TODO; is stub
type mfaInputs struct{}

func (m mfaInputs) ChooseFactor(factors []mfa.Config) (int, error) {
	log.Infof("got MFA factors: %v; choosing 0", factors)
	return 0, nil
}

func (m mfaInputs) CodeSupplier(factor mfa.Config) (string, error) {
	return "", nil
}

func (c *Client) DoAuth() error {
	// TODO
	if c.oldClient == nil {
		var err error
		c.oldClient, err = oldclient.NewOktaClient(
			oldclient.OktaCredential{
				Username: c.Creds.Username,
				Password: c.Creds.Password,
				Domain:   c.Creds.Domain,
				// TODO
				MFA: oldclientmfa.Config{
					DuoDevice: "phone1",
				},
			},
			nil,
			mfaInputs{},
			nil,
		)
		if err != nil {
			return fmt.Errorf("creating old client: %w", err)
		}
	}
	if err := c.oldClient.AuthenticateUser(); err != nil {
		return fmt.Errorf("authenticating user: %w", err)
	}
	c.Authed = true
	return nil
}

func (c *Client) Get(path string) (*http.Response, error) {
	if !c.Authed {
		err := c.DoAuth()
		if err != nil {
			return nil, fmt.Errorf("failed to auth during GET to %s: %w", err)
		}
	}
	// TODO: this needs to handle `onetimetoken` query param
	// we never use the JSON parsing AFAICT, and we always follow redirects
	return c.oldClient.Request("GET", path+"?onetimetoken="+c.oldClient.GetSessionToken(), url.Values{}, nil, "", true)
}
