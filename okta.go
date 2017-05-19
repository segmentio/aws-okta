package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/apex/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/segmentio/aws-okta/saml"
)

const (
	OktaOrganization = "segment"
	OktaAwsSAMLUrl   = "home/amazon_aws/0oa25q58sjnJXnvIg1t7/272"

	KeystoreName    = "aws-okta"
	KeystoreOktaKey = "okta-login"
	DefaultRegion   = "us-west-2"
)

type OktaClient struct {
	Organization    string
	Username        string
	Password        string
	UserAuth        *OktaUserAuthn
	DuoAuth         *DuoAuth
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type DuoAuth struct {
	Host      string
	Signature string
	Callback  string
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

func NewOktaClient(organization, username, password string) *OktaClient {
	return &OktaClient{
		Organization: organization,
		Username:     username,
		Password:     password,
	}
}

func (o *OktaClient) Authenticate(roleArn, profile string) (err error) {
	var payload []byte
	var oktaUserAuthn OktaUserAuthn
	var assertion SAMLAssertion
	var awsRoles []string

	// Step 1 : Basic authentication
	user := OktaUser{
		Username: o.Username,
		Password: o.Password,
	}

	payload, err = json.Marshal(user)
	if err != nil {
		return
	}

	err = o.Get("POST", "api/v1/authn", payload, &oktaUserAuthn, "json")
	if err != nil {
		return
	}

	o.UserAuth = &oktaUserAuthn

	// Step 2 : Challenge MFA if needed
	if o.UserAuth.Status == "MFA_REQUIRED" {
		err = o.challengeMFA()
	}

	if o.UserAuth.SessionToken == "" {
		err = fmt.Errorf("authentication failed for %s", o.Username)
		return
	}

	// Step 3 : Get SAML Assertion and retrieve IAM Roles
	assertion = SAMLAssertion{}
	err = o.Get("GET", OktaAwsSAMLUrl+"?onetimetoken="+o.UserAuth.SessionToken,
		nil, &assertion, "saml")
	if err != nil {
		return
	}

	awsRoles, err = GetRolesFromSAML(assertion.Resp)
	if err != nil {
		return
	}

	if len(awsRoles) == 0 {
		err = fmt.Errorf("do AWS Roles found for user %s\n", o.Username)
		return
	}
	awsRole := SelectAWSRoles(awsRoles)
	arns := strings.Split(awsRole, ",")

	// Step 4 : Assume Role with SAML
	samlSess := session.Must(session.NewSession())
	svc := sts.New(samlSess)

	log.Debugf("assuming first role with SAML : %v\n", arns)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(arns[0]),
		RoleArn:         aws.String(arns[1]),
		SAMLAssertion:   aws.String(string(assertion.RawData)),
		DurationSeconds: aws.Int64(3600),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", arns[0]).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return
	}

	// Step 5 : Chain to final Role and get temporary credentials
	client := sts.New(session.New(&aws.Config{Credentials: credentials.NewStaticCredentials(
		*samlResp.Credentials.AccessKeyId,
		*samlResp.Credentials.SecretAccessKey,
		*samlResp.Credentials.SessionToken,
	)}))

	log.Debugf("assuming role %s with profile %s\n", roleArn, profile)

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String("okta-" + profile),
	}
	resp, err := client.AssumeRole(params)
	if err != nil {
		log.WithField("role", roleArn).Errorf(
			"error assuming role: %s", err.Error())
		return
	}

	o.AccessKeyId = *resp.Credentials.AccessKeyId
	o.SecretAccessKey = *resp.Credentials.SecretAccessKey
	o.SessionToken = *resp.Credentials.SessionToken
	o.Expiration = *resp.Credentials.Expiration

	return
}

func (o *OktaClient) GetCredentials() (creds sts.Credentials, err error) {
	creds = sts.Credentials{
		AccessKeyId:     aws.String(o.AccessKeyId),
		SecretAccessKey: aws.String(o.SecretAccessKey),
		SessionToken:    aws.String(o.SessionToken),
		Expiration:      aws.Time(o.Expiration),
	}
	return
}

//TODO: The selection of the AWS role should be done using "source_role"
//		from the configuration
func SelectAWSRoles(roles []string) (role string) {
	return roles[0]
}

func (o *OktaClient) challengeMFA() (err error) {
	var oktaFactorId string
	var payload []byte
	var wg sync.WaitGroup

	for _, f := range o.UserAuth.Embedded.Factors {
		oktaFactorId, err = GetFactorId(&f)
	}
	if oktaFactorId == "" {
		return
	}

	payload, err = json.Marshal(OktaStateToken{
		StateToken: o.UserAuth.StateToken,
	})
	if err != nil {
		return
	}

	err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
		payload, &o.UserAuth, "json",
	)
	if err != nil {
		return
	}

	if o.UserAuth.Status == "MFA_CHALLENGE" {
		f := o.UserAuth.Embedded.Factor

		o.DuoAuth = &DuoAuth{
			Host:      f.Embedded.Verification.Host,
			Signature: f.Embedded.Verification.Signature,
			Callback:  f.Embedded.Verification.Links.Complete.Href,
		}

		log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
			f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
			o.UserAuth.StateToken)
		wg.Add(1)
		go func() {
			o.serveDuo()
		}()

		// Poll Okta until Duo authentication has been completed
		for o.UserAuth.Status != "SUCCESS" {
			err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
				payload, &o.UserAuth, "json",
			)
			if err != nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
		wg.Done()

		wg.Wait()
	}
	return
}

func (o *OktaClient) serveDuo() {
	http.HandleFunc("/duo", o.ServeTemplate)

	fmt.Printf("DUO U2F link : http://0.0.0.0:3000/duo\n\n")
	http.ListenAndServe(":3000", nil)
}

func (o *OktaClient) ServeTemplate(w http.ResponseWriter, r *http.Request) {
	var tmpl = template.Must(template.ParseFiles("templates/duo.html"))

	tmpl.ExecuteTemplate(w, "duo.html", map[string]interface{}{
		"StateToken": o.UserAuth.StateToken,
		"Host":       o.DuoAuth.Host,
		"Signature":  o.DuoAuth.Signature,
		"Callback":   o.DuoAuth.Callback,
	})
}

func GetFactorId(f *OktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	default:
		err = fmt.Errorf("factor %s not supported", f.FactorType)
	}
	return
}

func (o *OktaClient) Get(method string, path string, data []byte, recv interface{}, format string) (err error) {
	var url *url.URL
	var res *http.Response
	var body []byte
	var header http.Header
	var client http.Client
	var jar *cookiejar.Jar

	url, err = url.Parse(fmt.Sprintf(
		"https://%s.okta.com/%s", o.Organization, path,
	))

	if format == "json" {
		header = http.Header{
			"Accept":        []string{"application/json"},
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-cache"},
		}
	}

	jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return
	}
	client = http.Client{
		Jar: jar,
	}

	req := &http.Request{
		Method:        method,
		URL:           url,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(body)),
	}

	if res, err = client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", method, url, res.Status)
	} else if recv != nil {
		switch format {
		case "json":
			err = json.NewDecoder(res.Body).Decode(recv)
		default:
			var rawData []byte
			rawData, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return
			}
			err = ParseSAML(rawData, recv.(*SAMLAssertion))
		}
	}

	return
}
