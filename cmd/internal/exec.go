package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/segmentio/aws-okta/v2/cmd/internal/analytics"
	"github.com/segmentio/aws-okta/v2/cmd/internal/configload"
	awsokta "github.com/segmentio/aws-okta/v2/lib"
	"github.com/segmentio/aws-okta/v2/lib/assumerolewithsaml"
	"github.com/segmentio/aws-okta/v2/lib/oktaclient"
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec <profile> -- <command>",
	Short: "exec will run the command specified with aws credentials set in the environment",
	RunE:  execRun,
	/* TODO?
	PreRun: execPre,
	*/
	/* TODO? maybe lets just cut it out; this ends up causing us to load the config twice
	ValidArgs: listProfileNames(mustListProfiles()),
	*/
}

func init() {
	RootCmd.AddCommand(execCmd)
	// TODO: do we need this?
	execCmd.Flags().StringVarP(&FlagOktaAccountAlias, "account-alias", "", "", "Okta account alias (default `default`)")
	/* TODO
	execCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	execCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
	execCmd.Flags().StringVarP(&assumeRoleARN, "assume-role-arn", "r", "", "Role arn to assume, overrides arn in profile")
	*/
}

const AnalyticsCommandNameExec = "exec"

func execRun(cmd *cobra.Command, args []string) error {
	dashIx := cmd.ArgsLenAtDash()
	if dashIx == -1 || dashIx == len(args) {
		return fmt.Errorf("missing command")
	}

	args, commandPart := args[:dashIx], args[dashIx:]
	if len(args) != 1 {
		return &ErrBadArgCount{
			Actual:   len(args),
			Expected: 2,
		}
	}

	profileName := args[0]
	profiles, err := configload.FindAndParse()
	if err != nil {
		return err
	}

	profile, ok := profiles[profileName]
	if !ok {
		return fmt.Errorf("Profile '%s' not found in your AWS config. Use `list` to see configured profiles.", profileName)
	}

	sourceProfileName, ok := profile["source_profile"]
	// TODO: types
	var sourceProfile configload.Profile
	if ok {
		sourceProfile, ok = profiles[sourceProfileName]
		if !ok {
			return fmt.Errorf("Profile '%s' sources '%s', but it was not found.", profileName, sourceProfileName)
		}
	}

	/* TODO
	updateMfaConfig(cmd, profiles, profile, &mfaConfig)
	*/

	/* TODO
	// check for an assume_role_ttl in the profile if we don't have a more explicit one
	if !cmd.Flags().Lookup("assume-role-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, &assumeRoleTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse duration from profile config")
		}
	}
	*/

	Analytics.TrackRanCommand(AnalyticsCommandNameExec, [2]string{analytics.PropertyProfileName, profileName})

	accountAlias := FlagOktaAccountAlias
	if accountAlias == "" {
		accountAlias = "default"
	}
	oktaCreds, err := keyringCredsGet(accountAlias)
	if err != nil {
		return fmt.Errorf("Failed to get Okta creds from keyring; maybe try `add` first: %w", err)
	}

	var creds awsokta.AWSCreds
	if sourceProfileName == "" {
		// assume role with SAML
		oktaCl := oktaclient.Client{
			Creds: oktaCreds,
		}
		// TODO: use const
		samlURL, err := profiles.Get(profileName, "aws_saml_url")
		if err != nil {
			return fmt.Errorf("Failed to find aws_saml_url: %w", err)
		}
		opts := assumerolewithsaml.Opts{
			Region: FlagAWSRegion,
		}
		opts.ApplyDefaults()
		a := assumerolewithsaml.AssumeRoleWithSAML{
			OktaClient: oktaCl,
			AWSSAMLURL: samlURL,
			// TODO
			TargetRoleARNChooser: assumerolewithsaml.StaticChooser{profile["role_arn"]},
			Opts:                 opts,
		}
		credsSpecific, err := a.Assume()
		if err != nil {
			return fmt.Errorf("Failed to assume role: %w", err)
		}
		creds = credsSpecific.AWSCreds

	} else {
		_ = sourceProfile
		// TODO: assumerolewithsamlandcreds
	}

	env := kvEnv{}
	env.LoadFromEnviron(os.Environ()...)
	env.AddCreds(creds)
	env.AddInfo(infoEnvs{
		ProfileName: profileName,
		Region:      FlagAWSRegion,
		/* TODO
		BaseRoleARN:    creds.Meta.BaseRoleARN,
		AssumedRoleARN: creds.Meta.AssumedRoleARN,
		ExpiresAt:      creds.Meta.ExpiresAt,
		*/
	})

	command := commandPart[0]

	var commandArgs []string
	if len(commandPart) > 1 {
		commandArgs = commandPart[1:]
	}
	ecmd := exec.Command(command, commandArgs...)
	ecmd.Stdin = os.Stdin
	ecmd.Stdout = os.Stdout
	ecmd.Stderr = os.Stderr
	ecmd.Env = env.Environ()

	// Forward SIGINT, SIGTERM to the child command
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt)

	go func() {
		sig := <-sigChan
		if ecmd.Process != nil {
			ecmd.Process.Signal(sig)
		}
	}()

	var waitStatus syscall.WaitStatus
	if err := ecmd.Run(); err != nil {
		if err != nil {
			return err
		}
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			os.Exit(waitStatus.ExitStatus())
		}
	}
	return nil
}
