package oktasaml

import (
	"fmt"
	"io/ioutil"
	"net/http"

	awsokta "github.com/segmentio/aws-okta/v2/lib"
	"github.com/segmentio/aws-okta/v2/lib/oktaclient"
)

type Client struct {
	OktaClient oktaclient.Client

	SAMLURL string

	samlAssertionData []byte
}

// Gets SAML assertion and stores it in client
func (c *Client) GetSAMLAssertionData() ([]byte, error) {
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
	c.samlAssertionData = rawData
	return rawData, nil
}

// Parses assumable roels from SAML assertion. Will call GetSAMLAssertionData on your behalf
// if it hasn't been called yet
func (c *Client) GetAssumableRoles() ([]awsokta.AssumableRole, error) {
	if c.samlAssertionData != nil {
		if _, err := c.GetSAMLAssertionData(); err != nil {
			return nil, fmt.Errorf("getting SAML assertion: %w", err)
		}
	}
	samlAssertion, err := parse(c.samlAssertionData)
	if err != nil {
		return nil, fmt.Errorf("parsing SAML assertion: %w", err)
	}

	roles, err := samlAssertion.Resp.Assertion.getAssumableRoles()
	if err != nil {
		return nil, fmt.Errorf("finding assumable roles: %w", err)
	}

	return roles, nil
}
