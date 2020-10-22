package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
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
		return fmt.Errorf("Profile '%s' not found in your aws config. Use list command to see configured profiles", profile)
	}

	updateMfaConfig(cmd, profiles, profile, &mfaConfig)

	// check profile for both session durations if not explicitly set
	if !cmd.Flags().Lookup("assume-role-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, "assume_role_ttl", &assumeRoleTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse assume_role_ttl from profile config")
		}
	}

	if !cmd.Flags().Lookup("session-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, "session_ttl", &sessionTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse session_ttl from profile config")
		}
	}

	opts := lib.ProviderOptions{
		MFAConfig:          mfaConfig,
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
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

	opts.SessionCacheSingleItem = flagSessionCacheSingleItem

	p, err := lib.NewProvider(kr, profile, opts)
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
		Expiration:      p.GetExpiration().Format(time.RFC3339),
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
