package client

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	gock "gopkg.in/h2non/gock.v1"
)

func newSessionCache() *testSessionCache {
	return &testSessionCache{internalCache: map[string][]byte{}}
}

type testSessionCache struct {
	internalCache map[string][]byte
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
	oktaClient, err = NewOktaClient(creds, sCache, nil)
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
		isSessionValid, err := oktaClient.ValidateSession()
		if assert.NoError(t, err, "We can validate a session") {
			assert.Equal(t, true, isSessionValid, "Assert the session is valid if 200 returned")
		}
		gock.New("https://canada").
			Get("/api/v1/sessions/me").
			Reply(400)
		isSessionValid, err = oktaClient.ValidateSession()
		if assert.NoError(t, err, "We can validate a session") {
			assert.Equal(t, false, isSessionValid, "Assert the session is NOT valid if !200 returned")
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
}

func TestOktaClientNoSessionCache(t *testing.T) {
	var (
		oktaClient *OktaClient
		creds      OktaCredential
		err        error
		//		mfaConfig  MFAConfig
	)

	defer gock.Off()

	// uncomment this to get gock to dump all requests
	// gock.Observe(gock.DumpRequest)

	//
	// start setup
	//
	creds = OktaCredential{
		Domain:   "canada",
		Username: "john",
		Password: "johnnyjohn123",
	}
	oktaClient, err = NewOktaClient(creds, nil, nil)
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

	t.Run("test okta user auth flow with MFA", func(t *testing.T) {
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

		gock.New("https://canada").
			Post("/api/v1/authn/factors/fuf8y2l4n5mfH0UWe0h7/verify").
			Reply(200).BodyString(`{
   "stateToken":"00wCfuPA3qX3azDawSdPGFIhHuzbZX72Gv4bu_ew9d",
   "expiresAt":"2016-12-06T01:32:39.000Z",
   "status":"MFA_CHALLENGE",
   "_embedded":{
      "user":{
         "id":"00u21eb3qyRDNNIKTGCW",
         "passwordChanged":"2015-10-28T23:27:57.000Z",
         "profile":{
            "login":"first.last@gmail.com",
            "firstName":"First",
            "lastName":"Last",
            "locale":"en",
            "timeZone":"America/Los_Angeles"
         }
      },
      "factor":{
         "id":"fuf8y2l4n5mfH0UWe0h7",
         "factorType":"u2f",
         "provider":"FIDO",
         "vendorName":"FIDO",
         "profile":{
            "credentialId":"shvjvW2Fi2GtCJb33nm0105EISG9lf2Jg0jWl42URM6vtDH8-AhnoSKfpoHfAf0kJMaCx13glfdxiLFuPW_1bw",
            "appId":"https://${yourOktaDomain}",
            "version":"U2F_V2"
         },
         "_embedded":{
            "challenge":{
               "nonce":"tT1MI7XGzMu48Ivnz3vB",
               "timeoutSeconds":20
            }
         }
      },
      "policy":{
         "allowRememberDevice":true,
         "rememberDeviceLifetimeInMinutes":0,
         "rememberDeviceByDefault":false
      }
   },
   "_links":{
      "next":{
         "name":"verify",
         "href":"https://${yourOktaDomain}/api/v1/authn/factors/fuf8y2l4n5mfH0UWe0h7/verify",
         "hints":{
            "allow":[
               "POST"
            ]
         }
      },
      "cancel":{
         "href":"https://${yourOktaDomain}/api/v1/authn/cancel",
         "hints":{
            "allow":[
               "POST"
            ]
         }
      },
      "prev":{
         "href":"https://${yourOktaDomain}/api/v1/authn/previous",
         "hints":{
            "allow":[
               "POST"
            ]
         }
      }
   }
}`)

		oktaClient.creds.MFA = MFAConfig{
			Provider:   "YUBIKEY",
			FactorType: "u2f",
		}
		err = oktaClient.AuthenticateUser()
		t.Skip("Skip MFA test")
		if assert.NoError(t, err, "We're able to auth with MFA") {

			assert.Equal(t, "this-is-my-kebab-token", oktaClient.userAuth.SessionToken, "we're able to get a sessions token from the response")
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
		assert.Equal(t, fmt.Errorf("Password is expired, login to Okta console to change"), err)
	})

	t.Run("session interface returns a reasonable error", func(t *testing.T) {

		err = oktaClient.saveSessionCookie()
		assert.Equal(t, err, fmt.Errorf("Session NOT saved. Reason: Session Backend not defined"))

		err = oktaClient.retrieveSessionCookie()
		assert.Equal(t, err, fmt.Errorf("Session NOT retrieved. Reason: Session Backend not defined"))
	})
}
