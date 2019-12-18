package provider

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html"
)

var awsRoleARNRegex = regexp.MustCompile(`arn:[a-z-]+:iam::(\d{12}):role/(.*)`)

// TODO: document this mysterious monstrosity
// this is identical to the one found in duoclient, and comes from
// lib/utils.go pre-refactor
func getNode(n *html.Node, name string) (val string, node *html.Node) {
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
			val, node = getNode(c, name)
			if val != "" {
				return
			}
		}
	}
	return
}

func ParseSAML(body []byte, resp *SAMLAssertion) (err error) {
	var val string
	var data []byte
	var doc *html.Node
	doc, err = html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	val, _ = getNode(doc, "SAMLResponse")
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

func GetAssumableRolesFromSAML(resp *Response) (AssumableRoles, error) {
	roleList := []AssumableRole{}

	for _, a := range resp.Assertion.AttributeStatement.Attributes {
		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			for _, v := range a.AttributeValues {
				log.Debugf("Got SAML role attribute: %s", v.Value)
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
				if strings.Contains(tokens[0], ":saml-provider/") {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::ACCOUNT:saml-provider/provider,arn:aws:iam::account:role/roleName
					roleList = append(roleList, AssumableRole{Role: tokens[1],
						Principal: tokens[0]})
				} else if strings.Contains(tokens[1], ":saml-provider/") {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::account:role/roleName,arn:aws:iam::ACCOUNT:saml-provider/provider
					roleList = append(roleList, AssumableRole{Role: tokens[0],
						Principal: tokens[1]})
				} else {
					return AssumableRoles{}, fmt.Errorf("unable to get roles from %s", v.Value)
				}

			}
		}
	}
	return roleList, nil
}
