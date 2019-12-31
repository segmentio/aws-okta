package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/segmentio/aws-okta/v2/cmd/internal/analytics"
	awsokta "github.com/segmentio/aws-okta/v2/lib"
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

	/* TODO
	config, err := configload.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("profile '%s' not found in your aws config, use list command to see configured profiles", profile)
	}
	*/

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

	/* TODO
	opts := provider.AWSSAMLProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
		AssumeRoleArn:      assumeRoleARN,
	}


	p, err := createAWSSAMLProvider(backend, mfaConfig, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	roleARN, err := p.GetRoleARNWithRegion(creds)
	if err != nil {
		return err
	}
	*/
	p := awsokta.AWSCredsProvider{
		// TODO
		BaseRoleARN: "arn:aws:iam::1234567890:role/fake-role",
		Region:      "us-west-2",
	}
	creds, err := p.Refresh()
	if err != nil {
		return fmt.Errorf("failed to refresh credentials: %w", err)
	}

	env := kvEnv{}
	env.LoadFromEnviron(os.Environ()...)
	env.AddInfo(infoEnvs{
		ProfileName:    profileName,
		Region:         creds.Meta.Region,
		BaseRoleARN:    creds.Meta.BaseRoleARN,
		AssumedRoleARN: creds.Meta.AssumedRoleARN,
		ExpiresAt:      creds.Meta.ExpiresAt,
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
