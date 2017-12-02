package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/segmentio/aws-okta/lib"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login <profile>",
	Short: "login will authenticate you through okta and allow you to access your AWS environment through a browser",
	RunE:  loginRun,
}

func init() {
	RootCmd.AddCommand(loginCmd)
	loginCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	loginCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
}

func loginRun(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return ErrTooFewArguments
	}
	if len(args) > 1 {
		return ErrTooManyArguments
	}

	profile := args[0]

	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config", profile)
	}

	opts := lib.ProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	kr, err := keyring.Open("aws-okta", backend)
	if err != nil {
		return err
	}

	p, err := lib.NewProvider(kr, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    creds.AccessKeyID,
		"sessionKey":   creds.SecretAccessKey,
		"sessionToken": creds.SessionToken,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", "https://signin.aws.amazon.com/federation", nil)
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

	destination := "https://console.aws.amazon.com/"
	prof := profiles[profile]
	if region, ok := prof["region"]; ok {
		destination = fmt.Sprintf(
			"https://%s.console.aws.amazon.com/console/home?region=%s",
			region, region,
		)
	}

	loginURL := fmt.Sprintf(
		"https://signin.aws.amazon.com/federation?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	if err = open.Run(loginURL); err != nil {
		return err
	}
	return nil
}
