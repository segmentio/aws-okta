package oktasaml

import (
	"fmt"
	"io/ioutil"
	"net/http"

	awsokta "github.com/segmentio/aws-okta/v2/lib"
	"github.com/segmentio/aws-okta/v2/lib/oktaclient"
)

// Client is stateful. Methods cache their results. Call Reset
type Client struct {
	OktaClient oktaclient.Client

	SAMLURL string

	body []byte

	samlResponseB64 []byte
}

func (c *Client) Reset() {
	c.body = nil
	c.samlResponseB64 = nil

}

// Gets SAML assertion and stores it in client
func (c *Client) Get() ([]byte, error) {
	if c.body != nil {
		return c.body, nil
	}
	res, err := c.OktaClient.Get(c.SAMLURL)
	if err != nil {
		return nil, fmt.Errorf("GET SAML URL %s: %w", c.SAMLURL, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %v: %s", res.Request.URL, res.Status)
	}
	var rawData []byte
	rawData, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading SAML body: %w", err)
	}
	c.body = rawData
	return rawData, nil
}

func (c *Client) GetSAMLResponseB64() ([]byte, error) {
	if c.samlResponseB64 != nil {
		return c.samlResponseB64, nil
	}
	body, err := c.Get()
	if err != nil {
		return nil, err
	}

	r, err := parseSAMLResponseB64(body)
	if err != nil {
		return nil, err
	}
	c.samlResponseB64 = r
	return r, err
}

// Parses assumable roles from SAML assertion. Will call GetSAMLAssertionData on your behalf
// if it hasn't been called yet
func (c *Client) GetAssumableRoles() ([]awsokta.AssumableRole, error) {
	samlResponseB64, err := c.GetSAMLResponseB64()
	if err != nil {
		return nil, err
	}
	samlAssertion, err := parseSAMLAssertion(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("parsing SAML assertion: %w", err)
	}

	roles, err := samlAssertion.Resp.Assertion.getAssumableRoles()
	if err != nil {
		return nil, fmt.Errorf("finding assumable roles: %w", err)
	}

	return roles, nil
}
