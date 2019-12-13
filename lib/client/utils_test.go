package client

import (
	"errors"
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
		mfaIdTests := map[string]MFAConfig{
			"web": MFAConfig{
				Id:         "webId",
				FactorType: "web",
			},
			"token": MFAConfig{
				Id:         "tokenId",
				FactorType: "token",
				Provider:   "SYMANTEC",
			},
			"token:software:totp": MFAConfig{
				Id:         "token:software:totp:Id",
				FactorType: "token:software:totp",
			},
			"token:hardware": MFAConfig{
				Id:         "token:hardware:ID",
				FactorType: "token:hardware",
			},
			"sms": MFAConfig{
				Id:         "sms:ID",
				FactorType: "sms",
			},
			"u2f": MFAConfig{
				Id:         "u2f:ID",
				FactorType: "u2f",
			},
			"OKTA push": MFAConfig{
				Id:         "push:ID",
				FactorType: "push",
				Provider:   "OKTA",
			},
			"DUO push": MFAConfig{
				Id:         "push:ID",
				FactorType: "push",
				Provider:   "DUO",
			},
		}

		for factorType, authnFactor := range mfaIdTests {
			err := isFactorSupported(authnFactor)
			assert.NoError(t, err, fmt.Sprintf("Failure for factorType: %s", factorType))
		}
	})
	t.Run("MFA Factor id lookup error cases", func(t *testing.T) {
		mfaIdTests := map[string]MFAConfig{
			"token": MFAConfig{
				Id:         "tokenId",
				FactorType: "token",
				Provider:   "NOT SYMANTEC",
			},
			"push": MFAConfig{
				Id:         "push:ID",
				FactorType: "push",
				Provider:   "not DUO or OKTA",
			},
			"not supported": MFAConfig{
				FactorType: "not-supported",
			},
		}

		for factorType, authnFactor := range mfaIdTests {
			err := isFactorSupported(authnFactor)
			assert.Equal(t, true, errors.Is(err, ErrNotImplemented), "confirm we get the correct error for "+factorType)
		}
	})
}
