package lib

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/segmentio/aws-okta/lib/saml"
	"golang.org/x/net/html"
)

//TODO: Move those functions into saml package

func GetRoleFromSAML(resp *saml.Response, profileARN string) (string, string, error) {
	for _, a := range resp.Assertion.AttributeStatement.Attributes {
		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			for _, v := range a.AttributeValues {
				tokens := strings.Split(v.Value, ",")
				if len(tokens) != 2 {
					continue
				}

				// Amazon's documentation suggests that the
				// Role ARN should appear first in the comma-delimited
				// set in the Role Attribute that SAML IdP returns.
				//
				// See the section titled "An Attribute element with the Name attribute set
				// to https://aws.amazon.com/SAML/Attributes/Role" on this page:
				// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html
				//
				// In practice, though, Okta SAML integrations with AWS will succeed
				// with either the role or principal ARN first, and these `if` statements
				// allow that behavior in this program.
				if tokens[0] == profileARN {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::account:role/roleName,arn:aws:iam::ACCOUNT:saml-provider/provider
					return tokens[1], tokens[0], nil
				} else if tokens[1] == profileARN {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::ACCOUNT:saml-provider/provider,arn:aws:iam::account:role/roleName
					return tokens[0], tokens[1], nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("Role '%s' not authorized by Okta.  Contact Okta admin to make sure that the AWS app is configured properly.", profileARN)
}

func ParseSAML(body []byte, resp *SAMLAssertion) (err error) {
	var val string
	var data []byte
	var doc *html.Node

	doc, err = html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	val, _ = GetNode(doc, "SAMLResponse")
	if val != "" {
		resp.RawData = []byte(val)
		val = strings.Replace(val, "&#x2b;", "+", -1)
		val = strings.Replace(val, "&#x3d;", "=", -1)
		data, err = base64.StdEncoding.DecodeString(val)
		if err != nil {
			return
		}
	}

	err = xml.Unmarshal(data, &resp.Resp)

	return
}

func GetNode(n *html.Node, name string) (val string, node *html.Node) {
	var isMatch bool
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, a := range n.Attr {
			if a.Key == "name" && a.Val == name {
				isMatch = true
			}
			if a.Key == "value" && isMatch {
				val = a.Val
			}
		}
	}
	if node == nil || val == "" {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			val, node = GetNode(c, name)
			if val != "" {
				return
			}
		}
	}
	return
}
