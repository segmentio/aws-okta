package lib

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/segmentio/aws-okta/lib/saml"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html"
)

// Role arn format => arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}
// https://docs.aws.amazon.com/IAM/latest/UserGuide/list_identityandaccessmanagement.html
var awsRoleARNRegex = regexp.MustCompile(`arn:[a-z-]+:iam::(\d{12}):role/(.*)`)

func GetRoleFromSAML(resp *saml.Response, profileARN string) (string, string, error) {

	roles, err := GetAssumableRolesFromSAML(resp)
	if err != nil {
		return "", "", err
	}
	role, err := GetRole(roles, profileARN)
	if err != nil {
		return "", "", err
	}
	return role.Principal, role.Role, nil
}

func GetAssumableRolesFromSAML(resp *saml.Response) (saml.AssumableRoles, error) {
	roleList := []saml.AssumableRole{}

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
					roleList = append(roleList, saml.AssumableRole{Role: tokens[1],
						Principal: tokens[0]})
				} else if strings.Contains(tokens[1], ":saml-provider/") {
					// if true, Role attribute is formatted like:
					// arn:aws:iam::account:role/roleName,arn:aws:iam::ACCOUNT:saml-provider/provider
					roleList = append(roleList, saml.AssumableRole{Role: tokens[0],
						Principal: tokens[1]})
				} else {
					return saml.AssumableRoles{}, fmt.Errorf("Unable to get roles from %s", v.Value)
				}

			}
		}
	}
	return roleList, nil
}

func GetRole(roleList saml.AssumableRoles, profileARN string) (saml.AssumableRole, error) {

	// if the user doesn't have any roles they can assume return an error.
	if len(roleList) == 0 {
		return saml.AssumableRole{}, fmt.Errorf("There are no roles that can be assumed")
	}

	// A role arn was provided as part of the profile, we will assume that role.
	if profileARN != "" {
		for _, arole := range roleList {
			if profileARN == arole.Role {
				return arole, nil
			}
		}
		return saml.AssumableRole{}, fmt.Errorf("ARN isn't valid")
	}

	// if the user only has one role assume that role without prompting.
	if len(roleList) == 1 {
		return roleList[0], nil
	}

	// Sort the roles in alphabetical order
	sort.Slice(roleList, func(i, j int) bool {
		return roleList[i].Role < roleList[j].Role
	})

	var roleName, previousAccountID, currentAccountID string

	for i, arole := range roleList {
		currentAccountID, roleName = accountIDAndRoleFromRoleARN(arole.Role)
		if currentAccountID != previousAccountID {
			fmt.Printf("\nAccount: %s\n", currentAccountID)
		}
		previousAccountID = currentAccountID

		fmt.Printf("%4d - %s\n", i, roleName)
	}
	fmt.Println("")

	i, err := Prompt("Select Role to Assume", false)
	if err != nil {
		return saml.AssumableRole{}, err
	}
	if i == "" {
		return saml.AssumableRole{}, errors.New("Invalid selection - Please use an option that is listed")
	}
	factorIdx, err := strconv.Atoi(i)
	if err != nil {
		return saml.AssumableRole{}, err
	}
	if factorIdx > (len(roleList) - 1) {
		return saml.AssumableRole{}, errors.New("Invalid selection - Please use an option that is listed")
	}
	return roleList[factorIdx], nil
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

func accountIDAndRoleFromRoleARN(roleARN string) (string, string) {
	matches := awsRoleARNRegex.FindStringSubmatch(roleARN)

	// matches will contain ("roleARN", "accountID", "roleName")
	if len(matches) == 3 {
		return matches[1], matches[2]
	}

	// Getting here means we failed to extract accountID and roleName from
	// roleARN. It should "not" happen, but if it does, return empty string
	// as accountID and roleARN as roleName instead.
	return "", roleARN
}
