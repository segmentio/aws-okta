package okta

import (
	"encoding/base64"
	"encoding/xml"
	"strings"

	"github.com/segmentio/aws-okta/saml"
	"golang.org/x/net/html"
)

//TODO: Move those functions into saml package

func GetRolesFromSAML(resp *saml.Response) (roles []string, err error) {
	for _, a := range resp.Assertion.AttributeStatement.Attributes {
		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			for _, v := range a.AttributeValues {
				if roles == nil {
					roles = make([]string, 1)
				} else {
					newRoles := make([]string, len(roles)+1)
					copy(newRoles, roles)
					roles = newRoles
				}
				roles[len(roles)-1] = v.Value
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

	val, _ = GetNode(doc)
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

func GetNode(n *html.Node) (val string, node *html.Node) {
	var isSAML bool
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, a := range n.Attr {
			if a.Key == "name" && a.Val == "SAMLResponse" {
				isSAML = true
			}
			if a.Key == "value" && isSAML {
				val = a.Val
			}
		}
	}

	if node == nil || val == "" {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			val, node = GetNode(c)
			if val != "" {
				return
			}
		}
	}
	return
}
