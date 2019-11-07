package provider

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/internal/sessioncache"
	"github.com/stretchr/testify/assert"
	gock "gopkg.in/h2non/gock.v1"
	"testing"
)

type testOktaClient struct {
	client  http.Client
	baseURL string
}

func (c testOktaClient) AuthenticateUser() error {
	return nil
}
func (c testOktaClient) GetSessionToken() string {
	return "my-fake-session-token"
}
func (c testOktaClient) SaveSessionCookie() error {
	return nil
}
func (c testOktaClient) Request(method string, path string, queryParams url.Values, data []byte, format string, followRedirects bool) (*http.Response, error) {

	requestUrl, err := url.Parse(fmt.Sprintf(
		"%s/%s", c.baseURL, path,
	))

	requestUrl.RawQuery = queryParams.Encode()
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method:        method,
		URL:           requestUrl,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
	res, err := c.client.Do(req)
	return res, err
}
func (c testOktaClient) GetURL(path string) (*url.URL, error) {
	requestUrl, err := url.Parse(fmt.Sprintf(
		"%s/%s", c.baseURL, path,
	))
	if err != nil {
		return nil, err
	}
	return requestUrl, nil
}

func TestAWSSAMLProvider(t *testing.T) {
	defer gock.Off()
	var (
		oktaClient      testOktaClient
		err             error
		profile         string
		KrBackend       []keyring.BackendType
		awsSamlProvider *AWSSAMLProvider
	)
	//
	// start setup
	//

	// uncomment this to get gock to dump all requests
	//	gock.Observe(gock.DumpRequest)

	profile = "okta-test-profile"
	// we use a file backend for testing in a temp dir
	KrBackend = append(KrBackend, keyring.FileBackend)

	tempDir, err := ioutil.TempDir("", "aws-okta")
	assert.NoError(t, err, "create a temp dir to back the keyring")
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:          KrBackend,
		KeychainTrustApplication: true,
		ServiceName:              "aws-okta-login",
		LibSecretCollectionName:  "awsvault",
		FileDir:                  tempDir,
		FilePasswordFunc:         func(string) (string, error) { return "funkypass", nil }})
	assert.NoError(t, err, "No errors when opening a keyring")
	providerOptions := AWSSAMLProviderOptions{
		Profiles: map[string]map[string]string{
			profile: map[string]string{
				"role_arn":     "arn:aws:iam::000000000000:role/sharks.are.friends.samlrole",
				"aws_saml_url": "/a/saml/url",
			},
		},
	}
	oktaClient = testOktaClient{
		client:  http.Client{},
		baseURL: "https://canada",
	}
	sessions := &sessioncache.SingleKrItemStore{kr}
	awsSamlProvider, err = NewAWSSAMLProvider(sessions, profile, providerOptions, oktaClient)

	// intercept the http client with gock to mock out the Okta responses
	//gock.InterceptClient(&(awsSamlProvider.oktaClient.Client))

	//
	// end setup
	//

	t.Run("create the provider", func(t *testing.T) {

		assert.Equal(t,
			profile,
			awsSamlProvider.profile,
			"the profile is set correctly")
		assert.Equal(t,
			providerOptions.Profiles[profile]["role_arn"],
			awsSamlProvider.profileARN,
			"the profile arn is set correctly")
		assert.Equal(t, profile, awsSamlProvider.profile, "the profile is set correctly")
		assert.Equal(t, time.Duration(0), awsSamlProvider.ExpiryWindow, "Expiry Window is set correctly")
		assert.NotNil(t, awsSamlProvider.oktaClient, "confirm okta client creation")

	})
	t.Run("test parsing saml assertion", func(t *testing.T) {
		var samlAssertion SAMLAssertion
		//var expectedSamlAssertion SAMLAssertion
		var rawData []byte
		rawData, err = ioutil.ReadFile("test-resources/saml-test-data.html")
		assert.NoError(t, err, "able to read saml assertion data")

		err = ParseSAML(rawData, &samlAssertion)
		if assert.NoError(t, err, "able to parse saml assertion without errors") {
			assert.Equal(t, "", samlAssertion.Resp.SAMLP, "parsing samlp")
			assert.Equal(t, "", samlAssertion.Resp.SAML, "parsing saml")
			assert.Equal(t, "", samlAssertion.Resp.SAMLSIG, "parsing samlsig")
			assert.Equal(t, "http://localhost:8888/simplesamlphp/www/module.php/saml/sp/saml2-acs.php/example-okta-com", samlAssertion.Resp.Destination, "parsing destination")
		}
	})
	t.Run("provider helpers with default values", func(t *testing.T) {
		cookieKey := awsSamlProvider.getOktaSessionCookieKey()
		assert.Equal(t, "okta-session-cookie", cookieKey, "correct cookie key")
		accountName := awsSamlProvider.getOktaAccountName()
		assert.Equal(t, "okta-creds", accountName, "correct cookie key")

		loginURL, err := awsSamlProvider.GetSAMLLoginURL()
		if assert.NoError(t, err, "failed to get saml login url") {
			assert.Equal(t, "https://canada//a/saml/url", loginURL.String(), "able to get the saml login url")
		}
	})
	t.Run("test get call to aws app", func(t *testing.T) {
		gock.New("https://canada").
			Get("/a/saml/url").
			MatchParam("onetimetoken", "testing-token").
			Reply(200).
			File("test-resources/saml-test-data.html")
		queryParams := url.Values{}
		var samlAssertion SAMLAssertion

		queryParams.Set("onetimetoken", "testing-token")
		err = awsSamlProvider.getAWSSAML("/a/saml/url", queryParams, nil, &samlAssertion, "saml")
		if assert.NoError(t, err, "no errors when parsing saml assertion") {
			assert.Equal(t, "", samlAssertion.Resp.SAMLP, "parsing samlp")
			assert.Equal(t, "", samlAssertion.Resp.SAML, "parsing saml")
			assert.Equal(t, "", samlAssertion.Resp.SAMLSIG, "parsing samlsig")
			assert.Equal(t, "http://localhost:8888/simplesamlphp/www/module.php/saml/sp/saml2-acs.php/example-okta-com", samlAssertion.Resp.Destination, "parsing destination")
		}
	})
	t.Run("retrieve a token", func(t *testing.T) {
		gock.New("https://canada").
			Get("/a/saml/url").
			MatchParam("onetimetoken", "my-fake-session-token").
			Reply(200).
			File("test-resources/saml-test-data.html")

		gock.New("https://sts.amazonaws.com").
			Post("/").
			Reply(200).
			BodyString(`<AssumeRoleWithSAML xmlns="https://sts.amazonaws.com.cn/doc/2011-06-15/">
<AssumeRoleWithSAMLResult>
<Credentials>
  <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
  <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
  <Expiration>2011-07-11T19:55:29.611Z</Expiration>
  <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
</Credentials>
</AssumeRoleWithSAMLResult>
<ResponseMetadata>
<RequestId>58c5dbae-abef-11e0-8cfe-09039844ac7d</RequestId>
</ResponseMetadata>
</AssumeRoleWithSAML>`)
		stsCreds, err := awsSamlProvider.Retrieve()
		if assert.NoError(t, err, "Can retrieve without an error") {
			assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", stsCreds.AccessKeyID, "Check the sts credentials are set")
			assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY", stsCreds.SecretAccessKey, "Check the sts credentials are set")
			assert.Equal(t, "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE", stsCreds.SessionToken, "Check the sts credentials are set")
			assert.Equal(t, "okta", stsCreds.ProviderName, "Check the sts credentials are set")
		}

		gock.New("https://sts.amazonaws.com").
			Post("/").
			Reply(200).
			BodyString(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
   <Arn>arn:aws:iam::000000000000:role/sharks.are.friends.samlrole</Arn>
    <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`)
		roleArn, err := awsSamlProvider.GetRoleARNWithRegion(stsCreds)
		if assert.NoError(t, err, "Can retrieve without an error") {
			assert.Equal(t, providerOptions.Profiles[profile]["role_arn"], roleArn, "Confirm the role arn")
		}
		gock.New("https://sts.amazonaws.com").
			Post("/").
			Reply(200).
			BodyString(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
   <Arn>arn:aws:iam::000000000000:role/sharks.are.friends.samlrole</Arn>
    <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`)
		roleArn, err = GetRoleARN(stsCreds)
		if assert.NoError(t, err, "Can retrieve without an error") {
			assert.Equal(t, providerOptions.Profiles[profile]["role_arn"], roleArn, "Confirm the role arn")
		}
	})
}

func TestAWSSAMLProviderUtils(t *testing.T) {
	var (
		err error
	)
	//
	// start setup
	//

	//
	// end setup
	//

	t.Run("provider options success", func(t *testing.T) {
		providerOptions := AWSSAMLProviderOptions{}
		providerOptions.ApplyDefaults()
		err = providerOptions.Validate()
		if assert.NoError(t, err, "Got a provider options validation error") {
			assert.Equal(t, DefaultAssumeRoleDuration, providerOptions.AssumeRoleDuration)
			assert.Equal(t, DefaultSessionDuration, providerOptions.SessionDuration)
		}
	})

	t.Run("provider options errors", func(t *testing.T) {
		optionErrorTests := map[string]AWSSAMLProviderOptions{
			"SessionDuration too short error": AWSSAMLProviderOptions{
				SessionDuration: time.Second * 10,
			},
			"SessionDuration too long error": AWSSAMLProviderOptions{
				SessionDuration: time.Hour * 9000,
			},
			"AssumeRoleDuration too short error": AWSSAMLProviderOptions{
				SessionDuration:    time.Minute * 45,
				AssumeRoleDuration: time.Second * 30,
			},
			"AssumeRoleDuration too long error": AWSSAMLProviderOptions{
				SessionDuration:    time.Minute * 45,
				AssumeRoleDuration: time.Hour * 9000,
			},
		}
		for test, opts := range optionErrorTests {
			err = opts.Validate()
			assert.Error(t, err, "Correctly Failing validation. Case: "+test)
		}
	})
}

func TestAWSSAMLProviderCreateErrors(t *testing.T) {

	var (
		err       error
		profile   string
		KrBackend []keyring.BackendType
	)
	//
	// start setup
	//

	// uncomment this to get gock to dump all requests
	//	gock.Observe(gock.DumpRequest)

	profile = "okta-test-profile"
	// we use a file backend for testing in a temp dir
	KrBackend = append(KrBackend, keyring.FileBackend)

	tempDir, err := ioutil.TempDir("", "aws-okta")
	assert.NoError(t, err, "create a temp dir to back the keyring")
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends:          KrBackend,
		KeychainTrustApplication: true,
		ServiceName:              "aws-okta-login",
		LibSecretCollectionName:  "awsvault",
		FileDir:                  tempDir,
		FilePasswordFunc:         func(string) (string, error) { return "funkypass", nil }})
	assert.NoError(t, err, "No errors when opening a keyring")
	sessions := &sessioncache.SingleKrItemStore{kr}
	//
	// end setup
	//
	t.Run("create with invalid opts", func(t *testing.T) {

		_, err := NewAWSSAMLProvider(sessions, profile, AWSSAMLProviderOptions{SessionDuration: time.Second * 3}, testOktaClient{})
		assert.Equal(t, fmt.Errorf("Minimum session duration is 15m0s"), err)

	})
	t.Run("create with assume role arn, okta-creds, no saml url", func(t *testing.T) {

		_, err = NewAWSSAMLProvider(sessions, profile, AWSSAMLProviderOptions{AssumeRoleArn: "some fake arn"}, testOktaClient{})
		assert.Equal(t, fmt.Errorf("aws_saml_url missing from ~/.aws/config"), err)

	})
}
