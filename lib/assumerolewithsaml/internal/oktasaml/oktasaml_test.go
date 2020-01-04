package oktasaml

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSAMLAssertion(t *testing.T) {
	var rawData []byte
	rawData, err := ioutil.ReadFile("test-resources/saml-test-data.html")
	if !assert.NoError(t, err, "able to read saml assertion data") {
		t.FailNow()
	}

	s, err := parse(rawData)
	if !assert.NoError(t, err, "able to parse saml assertion without errors") {
		t.FailNow()
	}
	assert.Equal(t, "", s.Resp.SAMLP, "parsing samlp")
	assert.Equal(t, "", s.Resp.SAML, "parsing saml")
	assert.Equal(t, "", s.Resp.SAMLSIG, "parsing samlsig")
	assert.Equal(t, "http://localhost:8888/simplesamlphp/www/module.php/saml/sp/saml2-acs.php/example-okta-com", s.Resp.Destination, "parsing destination")
}
