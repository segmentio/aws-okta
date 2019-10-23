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

	t.Run("MFA Factor id lookup success cases", func(t *testing.T) {
		mfaIdTests := map[string]oktaUserAuthnFactor{
			"web": oktaUserAuthnFactor{
				Id:         "webId",
				FactorType: "web",
			},
			"token": oktaUserAuthnFactor{
				Id:         "tokenId",
				FactorType: "token",
				Provider:   "SYMANTEC",
			},
			"token:software:totp": oktaUserAuthnFactor{
				Id:         "token:software:totp:Id",
				FactorType: "token:software:totp",
			},
			"token:hardware": oktaUserAuthnFactor{
				Id:         "token:hardware:ID",
				FactorType: "token:hardware",
			},
			"sms": oktaUserAuthnFactor{
				Id:         "sms:ID",
				FactorType: "sms",
			},
			"u2f": oktaUserAuthnFactor{
				Id:         "u2f:ID",
				FactorType: "u2f",
			},
			"OKTA push": oktaUserAuthnFactor{
				Id:         "push:ID",
				FactorType: "push",
				Provider:   "OKTA",
			},
			"DUO push": oktaUserAuthnFactor{
				Id:         "push:ID",
				FactorType: "push",
				Provider:   "DUO",
			},
		}

		for factorType, authnFactor := range mfaIdTests {
			id, err := getFactorId(&authnFactor)
			if assert.NoError(t, err, fmt.Sprintf("Failure for factorType: %s", factorType)) {
				assert.Equal(t, authnFactor.Id, id, "confirm we get Id back")
			}
		}
	})
	t.Run("MFA Factor id lookup error cases", func(t *testing.T) {
		mfaIdTests := map[string]oktaUserAuthnFactor{
			"token": oktaUserAuthnFactor{
				Id:         "tokenId",
				FactorType: "token",
				Provider:   "NOT SYMANTEC",
			},
			"push": oktaUserAuthnFactor{
				Id:         "push:ID",
				FactorType: "push",
				Provider:   "not DUO or OKTA",
			},
		}

		for factorType, authnFactor := range mfaIdTests {
			_, err := getFactorId(&authnFactor)
			assert.Equal(t, err, fmt.Errorf("provider %s with factor %s not supported", authnFactor.Provider, authnFactor.FactorType), "confirm we get the correct error for "+factorType)
		}
		_, err := getFactorId(&oktaUserAuthnFactor{FactorType: "not-supported"})
		assert.Equal(t, err, fmt.Errorf("factor %s not supported", "not-supported"), "confirm we get the correct error")
	})
}
