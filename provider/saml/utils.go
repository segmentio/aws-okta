package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/net/html"
)

type SAMLStruct struct {
	Resp    *Response // struct of the SAMLResponse
	RawResp []byte    // raw base64 encoded SAMLResponse
}

type RolePrincipal struct {
	Role      string
	Principal string
}

type ByRole []RolePrincipal

func (a ByRole) Len() int           { return len(a) }
func (a ByRole) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByRole) Less(i, j int) bool { return a[i].Role < a[j].Role }

func RolesOf(rps []RolePrincipal) (roles []string) {
	for _, rp := range rps {
		roles = append(roles, rp.Role)
	}
	return
}

func GetRolesFromSAML(resp *Response) (roles []RolePrincipal, n int, err error) {
	for _, a := range resp.Assertion.AttributeStatement.Attributes {
		if strings.HasSuffix(a.Name, "SAML/Attributes/Role") {
			for _, v := range a.AttributeValues {
				tokens := strings.Split(v.Value, ",")
				if len(tokens) != 2 {
					continue
				}
				roles = append(roles, RolePrincipal{tokens[0], tokens[1]})
				n++
			}
		}
	}
	if n == 0 {
		err = fmt.Errorf("No roles not authorized by Keycloak. Contact keycloak admin to make sure that the AWS app is configured properly.")
	}
	sort.Sort(ByRole(roles))
	return
}

func Parse(body []byte, resp *SAMLStruct) (err error) {
	var val string
	var data []byte
	var doc *html.Node

	doc, err = html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	val, _ = getNode(doc)
	if val != "" {
		resp.RawResp = []byte(val)
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
