package provider

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/mulesoft-labs/aws-keycloak/provider/saml"
	"golang.org/x/net/html"
)

//TODO: Move those functions into saml package

func GetRolesFromSAML(resp *saml.Response) (roles []string, principals []string, n int, err error) {
	for _, a := range resp.Assertion.AttributeStatement.Attributes {
		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			for _, v := range a.AttributeValues {
				tokens := strings.Split(v.Value, ",")
				if len(tokens) != 2 {
					continue
				}
				roles = append(roles, tokens[0])
				principals = append(principals, tokens[1])
				n++
			}
		}
	}
	if n == 0 {
		err = fmt.Errorf("No roles not authorized by Keycloak. Contact keycloak admin to make sure that the AWS app is configured properly.")
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

	val, _ = getNode(doc)
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

func getNode(n *html.Node) (val string, node *html.Node) {
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
			val, node = getNode(c)
			if val != "" {
				return
			}
		}
	}
	return
}
