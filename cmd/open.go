package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
)

const (
	govRegion = "us-gov-west-1"
	awsDomain = "aws.amazon.com"
	govDomain = "amazonaws-us-gov.com"
)

var openCmd = &cobra.Command{
	Use:     "open [profile]",
	Aliases: []string{"login"},
	Short:   "Open a AWS console logged into a given profile",
	Example: "  aws-keycloak open power-devx",
	RunE:    runOpenCmd,
}

func init() {
	RootCmd.AddCommand(openCmd)
}

func runOpenCmd(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return ErrTooManyArguments
	}

	stscreds, err := getAwsStsCreds()
	if err != nil {
		return err
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    *stscreds.AccessKeyId,
		"sessionKey":   *stscreds.SecretAccessKey,
		"sessionToken": *stscreds.SessionToken,
	})

	if err != nil {
		return err
	}

	var domain string
	if region == govRegion {
		domain = govDomain
	} else {
		domain = awsDomain
	}
	signin := fmt.Sprintf("https://signin.%s/federation", domain)
	destination := fmt.Sprintf("https://console.%s", domain)

	req, err := http.NewRequest("GET", signin, nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Call to getSigninToken failed with %v", resp.Status)
	}

	var respParsed map[string]string
	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		return err
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		return err
	}

	loginURL := fmt.Sprintf(
		"%s?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		signin,
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	return open.Run(loginURL)
}
