package client

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	gock "gopkg.in/h2non/gock.v1"

	"github.com/segmentio/aws-okta/lib/client/mfa"
	"github.com/segmentio/aws-okta/lib/client/types"
	log "github.com/sirupsen/logrus"
)

func newSessionCache() *testSessionCache {
	return &testSessionCache{internalCache: map[string][]byte{}}
}

type testSessionCache struct {
	internalCache map[string][]byte
}

type testMFAInputs struct {
	FactorIndex int
	Code        string

	ChooseFactorError error
	CodeSupplierError error
}

func (i testMFAInputs) ChooseFactor(factors []mfa.Config) (int, error) {
	return i.FactorIndex, i.ChooseFactorError
}

func (i testMFAInputs) CodeSupplier(factor mfa.Config) (string, error) {
	return i.Code, i.CodeSupplierError
}

func (s *testSessionCache) Get(key string) ([]byte, error) {
	item, ok := s.internalCache[key]
	if !ok {
		return []byte{}, fmt.Errorf("Item not found")
	}
	return item, nil
}
func (s *testSessionCache) Put(key string, data []byte, label string) error {
	s.internalCache[key] = data
	return nil
}

func TestOktaClientHappy(t *testing.T) {
	var (
		oktaClient *OktaClient
		creds      OktaCredential
		sCache     *testSessionCache
		err        error
		mfaInputs  testMFAInputs
	)

	defer gock.Off()

	// uncomment this to get gock to dump all requests
	//	gock.Observe(gock.DumpRequest)

	//
	// start setup
	//
	creds = OktaCredential{
		Domain:   "canada",
		Username: "john",
		Password: "johnnyjohn123",
	}

	sCache = newSessionCache()
	mfaInputs = testMFAInputs{}
	oktaClient, err = NewOktaClient(creds, sCache, mfaInputs, nil)
	assert.NoError(t, err, "No errors when creating a client")

	// intercept the http client with gock to mock out the Okta responses
	gock.InterceptClient(&(oktaClient.client))

	//
	// end setup
	//

	t.Run("validate okta client", func(t *testing.T) {
		assert.NotNil(t, oktaClient.BaseURL, "BaseURL is set")
		assert.Equal(t, "https://canada", oktaClient.BaseURL.String(), "Base URL should match")
	})

	t.Run("KeyringKey includes username", func(t *testing.T) {
		keyringKey := oktaClient.getSessionCookieKeyringKey()
		assert.Equal(t, "okta-session-cookie-john-canada", keyringKey, "session should be keyed on username")
	})

	t.Run("session tests", func(t *testing.T) {
		tokenData := "johnnyToken"
		err = sCache.Put(oktaClient.getSessionCookieKeyringKey(), []byte(tokenData), "okta testing cookie")
		assert.NoError(t, err, "Set cache item")

		err = oktaClient.retrieveSessionCookie()
		if assert.NoError(t, err, "Can retrieve sessions without errors") {
			assert.Equal(t, tokenData, oktaClient.client.Jar.Cookies(oktaClient.BaseURL)[0].Value, "Base URL should match")
		}

		tokenData = "newTokenData"
		oktaClient.client.Jar.SetCookies(oktaClient.BaseURL, []*http.Cookie{
			{
				Name:  "sid",
				Value: string(tokenData),
			},
		})
		err = oktaClient.saveSessionCookie()

		if assert.NoError(t, err, "Can save sessions without errors") {

			assert.Equal(t, tokenData, oktaClient.client.Jar.Cookies(oktaClient.BaseURL)[0].Value, "Base URL should match")
		}
	})
	t.Run("test okta session validity", func(t *testing.T) {
		gock.New("https://canada").
			Get("/api/v1/sessions/me").
			Reply(200)
		err := oktaClient.ValidateSession()
		assert.NoError(t, err, "The session is valid")

		gock.New("https://canada").
			Get("/api/v1/sessions/me").
			Reply(404)
		err = oktaClient.ValidateSession()
		if assert.Error(t, err, "The session is NOT valid") {
			assert.Equal(t, true, errors.Is(err, types.ErrInvalidSession), "Assert the session is NOT valid if 404 returned")
		}
		gock.New("https://canada").
			Get("/api/v1/sessions/me").
			Reply(500)
		err = oktaClient.ValidateSession()
		if assert.Error(t, err, "The session is NOT valid") {
			assert.Equal(t, true, errors.Is(err, types.ErrUnexpectedResponse), "Assert we get an unexpected response error.")
		}

	})

	t.Run("test okta user auth flow no MFA", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "SUCCESS",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "sessionToken": "this-is-my-kebab-token",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    }
  }
}`)
		err = oktaClient.AuthenticateUser()
		if assert.NoError(t, err, "We're able to auth without MFA") {

			assert.Equal(t, "this-is-my-kebab-token", oktaClient.userAuth.SessionToken, "we're able to get a sessions token from the response")
		}
	})
	t.Run("test okta user auth failure", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(401).BodyString(`{
  "errorCode": "E0000004",
  "errorSummary": "Authentication failed",
  "errorLink": "E0000004",
  "errorId": "oaeuHRrvMnuRga5UzpKIOhKpQ",
  "errorCauses": []
}`)
		err = oktaClient.AuthenticateUser()
		if assert.Error(t, err, "Auth Failure returns an error") {
			assert.Equal(t, true, errors.Is(err, types.ErrInvalidCredentials), "We get an invalid credentials error for 401")
		}
	})
}

func TestOktaClientNoSessionCache(t *testing.T) {
	var (
		oktaClient *OktaClient
		creds      OktaCredential
		err        error
		mfaInputs  testMFAInputs
	)

	// enable debug logs
	log.SetLevel(log.DebugLevel)
	defer gock.Off()

	// uncomment this to get gock to dump all requests
	gock.Observe(gock.DumpRequest)

	//
	// start setup
	//
	creds = OktaCredential{
		Domain:   "canada",
		Username: "john",
		Password: "johnnyjohn123",
	}
	mfaInputs = testMFAInputs{Code: "12345"}
	//mfaInputs.Code = "12345"
	oktaClient, err = NewOktaClient(creds, nil, mfaInputs, nil)
	assert.NoError(t, err, "No errors when creating a client")

	// intercept the http client with gock to mock out the Okta responses
	gock.InterceptClient(&(oktaClient.client))

	//
	// end setup
	//
	t.Run("test okta user auth flow no MFA", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "SUCCESS",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "sessionToken": "this-is-my-kebab-token",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    }
  }
}`)
		err = oktaClient.AuthenticateUser()
		if assert.NoError(t, err, "We're able to auth without MFA") {

			assert.Equal(t, "this-is-my-kebab-token", oktaClient.userAuth.SessionToken, "we're able to get a sessions token from the response")
		}
	})

	t.Run("MFA config doesn't match what is returned by Okta.", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb",
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "MFA_REQUIRED",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factors": [
      {
        "id": "fuf8y2l4n5mfH0UWe0h7",
        "factorType": "u2f",
        "provider": "FIDO",
        "profile": {
          "credentialId": "dade.murphy@example.com"
        },
        "_links": {
          "verify": {
            "href": "https://${yourOktaDomain}/api/v1/authn/factors/rsalhpMQVYKHZKXZJQEW/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      }
    ]
  },
  "_links": {
    "cancel": {
      "href": "https://${yourOktaDomain}/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}`)

		oktaClient.creds.MFA = mfa.Config{
			Provider:   "OKTA",
			FactorType: "sms",
		}
		err = oktaClient.AuthenticateUser()
		//t.Skip("Skip MFA test")
		if assert.Error(t, err, "we return an Error if MFA config doesn't match okta factors") {

			assert.Equal(t, true, errors.Is(err, types.ErrInvalidCredentials), "got creds type err")
		}
	})
	t.Run("test okta user auth flow with SMS MFA", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb",
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "MFA_REQUIRED",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factors": [
      {
        "id": "fuf8y2l4n5mfH0UWe0h7",
        "factorType": "sms",
        "provider": "OKTA",
        "profile": {
          "credentialId": "dade.murphy@example.com"
        },
        "_links": {
          "verify": {
            "href": "https://${yourOktaDomain}/api/v1/authn/factors/rsalhpMQVYKHZKXZJQEW/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      }
    ]
  },
  "_links": {
    "cancel": {
      "href": "https://${yourOktaDomain}/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}`)

		gock.New("https://canada").
			Post("api/v1/authn/factors/fuf8y2l4n5mfH0UWe0h7/verify").
			JSON(map[string]string{"stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb"}).
			Reply(200).BodyString(`{
  "stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb",
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "MFA_CHALLENGE",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factor": {
      "id": "fuf8y2l4n5mfH0UWe0h7",
      "factorType": "sms",
      "provider": "OKTA",
      "profile": {
        "phoneNumber": "+1 XXX-XXX-1337"
      }
    }
  },
  "_links": {
    "next": {
      "name": "verify",
      "href": "https://${yourOktaDomain}/api/v1/authn/factors/sms193zUBEROPBNZKPPE/verify",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "cancel": {
      "href": "https://${yourOktaDomain}/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "prev": {
      "href": "https://${yourOktaDomain}/api/v1/authn/previous",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "resend": [
      {
        "name": "sms",
        "href": "https://${yourOktaDomain}/api/v1/authn/factors/sms193zUBEROPBNZKPPE/verify/resend",
        "hints": {
          "allow": [
            "POST"
          ]
        }
      }
    ]
  }
}`)
		// set the response code and expect it to get to Okta.
		mfaInputs.Code = "12345"
		oktaClient.selector = mfaInputs
		gock.New("https://canada").
			Post("api/v1/authn/factors/fuf8y2l4n5mfH0UWe0h7/verify").
			JSON(map[string]string{"stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb", "passCode": mfaInputs.Code}).
			Reply(200).BodyString(`{
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "SUCCESS",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "sessionToken": "this-is-my-kebab-token",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    }
  }
}`)

		oktaClient.creds.MFA = mfa.Config{
			Provider:   "OKTA",
			FactorType: "sms",
		}
		err = oktaClient.AuthenticateUser()
		if assert.NoError(t, err, "We're able to auth with MFA") {

			assert.Equal(t, "this-is-my-kebab-token", oktaClient.userAuth.SessionToken, "we're able to get a sessions token from the response")
		}
	})
	t.Run("test okta user auth flow with TOTP MFA", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb",
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "MFA_REQUIRED",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factors": [
      {
        "id": "fuf8y2l4n5mfH0UWe0h7",
        "factorType": "token:software:totp",
        "provider": "OKTA",
        "profile": {
          "credentialId": "dade.murphy@example.com"
        },
        "_links": {
          "verify": {
            "href": "https://${yourOktaDomain}/api/v1/authn/factors/rsalhpMQVYKHZKXZJQEW/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      }
    ]
  },
  "_links": {
    "cancel": {
      "href": "https://${yourOktaDomain}/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}`)

		// set the response code and expect it to get to Okta.
		gock.New("https://canada").
			Post("api/v1/authn/factors/fuf8y2l4n5mfH0UWe0h7/verify").
			JSON(map[string]string{"stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb", "passCode": mfaInputs.Code}).
			Reply(200).BodyString(`{
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "SUCCESS",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "sessionToken": "this-is-my-kebab-token",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    }
  }
}`)

		oktaClient.creds.MFA = mfa.Config{
			Provider:   "OKTA",
			FactorType: "token:software:totp",
		}
		err = oktaClient.AuthenticateUser()
		if assert.NoError(t, err, "We're able to auth with MFA") {
			assert.Equal(t, "this-is-my-kebab-token", oktaClient.userAuth.SessionToken, "we're able to get a sessions token from the response")
		}
	})
	t.Run("test okta user auth flow with TOTP MFA invalid pass code", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb",
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "MFA_REQUIRED",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    },
    "factors": [
      {
        "id": "fuf8y2l4n5mfH0UWe0h7",
        "factorType": "token:software:totp",
        "provider": "OKTA",
        "profile": {
          "credentialId": "dade.murphy@example.com"
        },
        "_links": {
          "verify": {
            "href": "https://${yourOktaDomain}/api/v1/authn/factors/rsalhpMQVYKHZKXZJQEW/verify",
            "hints": {
              "allow": [
                "POST"
              ]
            }
          }
        }
      }
    ]
  },
  "_links": {
    "cancel": {
      "href": "https://${yourOktaDomain}/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}`)

		// set the response code and expect it to get to Okta.
		//		mfaInputs.Code = "invalid-pass-code"
		//		oktaClient.selector = mfaInputs
		gock.New("https://canada").
			Post("api/v1/authn/factors/fuf8y2l4n5mfH0UWe0h7/verify").
			JSON(map[string]string{"stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb", "passCode": "12345"}).
			Reply(403).BodyString(`{
  "errorCode": "E0000068",
  "errorSummary": "Invalid Passcode/Answer",
  "errorLink": "E0000068",
  "errorId": "oaei_IfXcpnTHit_YEKGInpFw",
  "errorCauses": [
    {
      "errorSummary": "Your passcode doesn't match our records. Please try again."
    }
  ]
}`)

		oktaClient.creds.MFA = mfa.Config{
			Provider:   "OKTA",
			FactorType: "token:software:totp",
		}
		err = oktaClient.AuthenticateUser()
		if assert.Error(t, err, "we get an error if pass code is invalid") {
			log.Debug("---------------------------------------")
			log.Debug(err)
			log.Debug("---------------------------------------")
			assert.Equal(t, true, errors.Is(err, types.ErrInvalidCredentials), "we get an error if the passcode is wrong")
		}
	})
	t.Run("okta user auth, expired password flow no MFA", func(t *testing.T) {
		gock.New("https://canada").
			Post("/api/v1/authn").
			JSON(map[string]string{"username": creds.Username, "password": creds.Password}).
			Reply(200).BodyString(`{
  "stateToken": "007ucIX7PATyn94hsHfOLVaXAmOBkKHWnOOLG43bsb",
  "expiresAt": "2015-11-03T10:15:57.000Z",
  "status": "PASSWORD_EXPIRED",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "_embedded": {
    "user": {
      "id": "00ub0oNGTSWTBKOLGLNR",
      "passwordChanged": "2015-09-08T20:14:45.000Z",
      "profile": {
        "login": "dade.murphy@example.com",
        "firstName": "Dade",
        "lastName": "Murphy",
        "locale": "en_US",
        "timeZone": "America/Los_Angeles"
      }
    },
    "policy": {
      "complexity": {
        "minLength": 8,
        "minLowerCase": 1,
        "minUpperCase": 1,
        "minNumber": 1,
        "minSymbol": 0
      }
    }
  },
  "_links": {
    "next": {
      "name": "changePassword",
      "href": "https://${yourOktaDomain}/api/v1/authn/credentials/change_password",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    },
    "cancel": {
      "href": "https://${yourOktaDomain}/api/v1/authn/cancel",
      "hints": {
        "allow": [
          "POST"
        ]
      }
    }
  }
}`)
		// this would only test the unlikely case where the user doesn't have MFA setup.
		// https://developer.okta.com/docs/reference/api/authn/#primary-authentication-with-public-application
		err = oktaClient.AuthenticateUser()
		assert.Equal(t, true, errors.Is(err, types.ErrInvalidCredentials), "verify we get an invalid creds error when password expired")
	})

	t.Run("session interface returns a reasonable error", func(t *testing.T) {

		err = oktaClient.saveSessionCookie()
		assert.Equal(t, err, fmt.Errorf("session NOT saved. Reason: Session Backend not defined"))

		err = oktaClient.retrieveSessionCookie()
		assert.Equal(t, err, fmt.Errorf("session NOT retrieved. Reason: Session Backend not defined"))
	})
}
