package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/99designs/keyring"
	"github.com/alessio/shellescape"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

// envCmd represents the env command
var envCmd = &cobra.Command{
	Use:       "env <profile>",
	Short:     "env prints out export commands for the specified profile",
	RunE:      envRun,
	Example:   "source <$(aws-okta env test)",
	ValidArgs: listProfileNames(mustListProfiles()),
}

func init() {
	RootCmd.AddCommand(envCmd)
	envCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	envCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
}

func envRun(cmd *cobra.Command, args []string) error {
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

	// check for an assume_role_ttl in the profile if we don't have a more explicit one
	if !cmd.Flags().Lookup("assume-role-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, &assumeRoleTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse duration from profile config")
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
				Set("command", "env"),
		})
	}

	p, err := lib.NewProvider(kr, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", shellescape.Quote(creds.AccessKeyID))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", shellescape.Quote(creds.SecretAccessKey))
	fmt.Printf("export AWS_OKTA_PROFILE=%s\n", shellescape.Quote(profile))

	if region, ok := profiles[profile]["region"]; ok {
		fmt.Printf("export AWS_DEFAULT_REGION=%s\n", shellescape.Quote(region))
		fmt.Printf("export AWS_REGION=%s\n", shellescape.Quote(region))
	}

	if creds.SessionToken != "" {
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", shellescape.Quote(creds.SessionToken))
		fmt.Printf("export AWS_SECURITY_TOKEN=%s\n", shellescape.Quote(creds.SessionToken))
	}

	return nil
}
