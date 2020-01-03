package oktasaml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	logrus "github.com/sirupsen/logrus"
	"golang.org/x/net/html"

	awsokta "github.com/segmentio/aws-okta/v2/lib"
)

// TODO: allow customization?
var log = logrus.StandardLogger().WithFields(logrus.Fields{"part": "oktasaml"})

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

func parseSAMLResponseB64(body []byte) ([]byte, error) {
	var val string
	var doc *html.Node
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parsing html: %w", err)
	}

	val, _ = getNode(doc, "SAMLResponse")
	if val == "" {
		log.Tracef("SAML doc: %s", body)
		return nil, fmt.Errorf("missing SAMLResponse node")

	}

	//TODO: poor man's XML entity decoding?
	val = strings.Replace(val, "&#x2b;", "+", -1)
	val = strings.Replace(val, "&#x3d;", "=", -1)
	return []byte(val), nil
}

func parseSAMLAssertion(samlResponseB64 []byte) (*SAMLAssertion, error) {
	var resp SAMLAssertion
	// TODO: not sure why we do this
	resp.RawData = []byte(samlResponseB64)

	data, err := base64.StdEncoding.DecodeString(string(samlResponseB64))
	if err != nil {
		return nil, fmt.Errorf("decoding SAML response: %w", err)
	}

	err = xml.Unmarshal(data, &resp.Resp)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling xml: %w", err)
	}
	return &resp, nil
}

func (s Assertion) getAssumableRoles() ([]awsokta.AssumableRole, error) {
	roleList := []awsokta.AssumableRole{}

	for _, a := range s.AttributeStatement.Attributes {
		if !strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			continue
		}
		for _, v := range a.AttributeValues {
			log.Tracef("Got SAML role attribute: %s", v.Value)
			tokens := strings.Split(v.Value, ",")
			if len(tokens) != 2 {
				continue
			}

			// role may come first or second
			if strings.Contains(tokens[0], ":saml-provider/") {
				roleList = append(roleList, awsokta.AssumableRole{Role: tokens[1], Principal: tokens[0]})
			} else if strings.Contains(tokens[1], ":saml-provider/") {
				roleList = append(roleList, awsokta.AssumableRole{Role: tokens[0], Principal: tokens[1]})
			} else {
				// TODO: should this just skip?
				return nil, fmt.Errorf("value missing 'saml-provider' token: %s", v.Value)
			}
		}
	}
	return roleList, nil
}
