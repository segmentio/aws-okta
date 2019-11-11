package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/provider"
	"github.com/spf13/cobra"
)

const credProcessVersion = 1

var pretty bool

type credProcess struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// credProcessCmd represents the cred-process command
var credProcessCmd = &cobra.Command{
	Use:       "cred-process <profile>",
	Short:     "cred-process generates a credential_process ready output",
	RunE:      credProcessRun,
	Example:   "[profile foo]\ncredential_process = aws-okta cred-process profile",
	ValidArgs: listProfileNames(mustListProfiles()),
}

func init() {
	RootCmd.AddCommand(credProcessCmd)
	credProcessCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	credProcessCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
	credProcessCmd.Flags().BoolVarP(&pretty, "pretty", "p", false, "Pretty print display")
}

func credProcessRun(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return ErrTooFewArguments
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
		return fmt.Errorf("profile '%s' not found in your aws config. Use list command to see configured profiles", profile)
	}

	updateMfaConfig(cmd, profiles, profile, &mfaConfig)

	// check for an assume_role_ttl in the profile if we don't have a more explicit one
	if !cmd.Flags().Lookup("assume-role-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, &assumeRoleTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse duration from profile config")
		}
	}

	opts := provider.AWSSAMLProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Ran Command",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("profile", profile).
				Set("command", "cred-process"),
		})
	}

	p, err := createAWSSAMLProvider(backend, mfaConfig, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	// builds the result struct
	cp := credProcess{
		Version:         credProcessVersion,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		// reuse the provided session duration
		Expiration: time.Now().Add(p.SessionDuration).Format(time.RFC3339),
	}

	var output []byte

	if pretty {
		output, err = json.MarshalIndent(cp, "", "    ")
	} else {
		output, err = json.Marshal(cp)
	}

	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}
