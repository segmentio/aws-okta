package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOktaClientUtils(t *testing.T) {

	//
	// start setup
	//
	// ---
	//
	// end setup
	//

	t.Run("valid regions", func(t *testing.T) {
		domainTests := map[string]string{
			"us":      "okta.com",
			"emea":    "okta-emea.com",
			"preview": "oktapreview.com",
		}
		for region, expectedDomain := range domainTests {
			oktaDomain, err := GetOktaDomain(region)
			if assert.NoError(t, err, "Got an error while using a valid region") {
				assert.Equal(t, expectedDomain, oktaDomain)
			}
		}
	})

	t.Run("invalid regions", func(t *testing.T) {
		domainTests := map[string]error{
			"canada": fmt.Errorf("invalid region %s", "canada"),
		}

		for region, expectedError := range domainTests {
			_, err := GetOktaDomain(region)
			assert.Equal(t, expectedError, err, "We get the correct error for invalid domains")
		}
	})
}
