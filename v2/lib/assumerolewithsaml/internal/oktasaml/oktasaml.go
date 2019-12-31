package oktasaml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html"

	awsokta "github.com/segmentio/aws-okta/v2/lib"
)

type SAMLAssertion struct {
	Resp *Response
	// TODO: this is weird
	RawData []byte
}

type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:saml2p,attr"`
	SAML         string `xml:"xmlns:saml2,attr"`
	SAMLSIG      string `xml:"xmlns:saml2sig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Assertion Assertion `xml:"Assertion"`
	Status    Status    `xml:"Status"`
}

type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	SAML               string `xml:"saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
}

type Conditions struct {
	XMLName      xml.Name
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
}

type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type NameID struct {
	XMLName xml.Name
	Format  string `xml:",attr"`
	Value   string `xml:",innerxml"`
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}

type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

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

func parse(body []byte) (*SAMLAssertion, error) {
	var val string
	var resp SAMLAssertion
	var data []byte
	var doc *html.Node
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("parsing html: %w", err)
	}

	val, _ = getNode(doc, "SAMLResponse")
	if val == "" {
		log.Debugf("SAML doc: %s", body)
		return nil, fmt.Errorf("missing SAMLResponse node")

	}
	// TODO: this is weird
	resp.RawData = []byte(val)
	val = strings.Replace(val, "&#x2b;", "+", -1)
	val = strings.Replace(val, "&#x3d;", "=", -1)
	data, err = base64.StdEncoding.DecodeString(val)
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
			log.Debugf("Got SAML role attribute: %s", v.Value)
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
