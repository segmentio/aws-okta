package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

var (
	sessionTTL    time.Duration
	assumeRoleTTL time.Duration
	assumeRoleARN string
)

func mustListProfiles() lib.Profiles {
	profiles, err := listProfiles()
	if err != nil {
		log.Panicf("Failed to list profiles: %v", err)
	}
	return profiles
}

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:       "exec <profile> -- <command>",
	Short:     "exec will run the command specified with aws credentials set in the environment",
	RunE:      execRun,
	PreRun:    execPre,
	ValidArgs: listProfileNames(mustListProfiles()),
}

func init() {
	RootCmd.AddCommand(execCmd)
	execCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	execCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
	execCmd.Flags().StringVarP(&assumeRoleARN, "assume-role-arn", "r", "", "Role arn to assume, overrides arn in profile")
}

func loadDurationFlagFromEnv(cmd *cobra.Command, flagName string, envVar string, val *time.Duration) error {
	if cmd.Flags().Lookup(flagName).Changed {
		return nil
	}

	fromEnv, ok := os.LookupEnv(envVar)
	if !ok {
		return nil
	}

	dur, err := time.ParseDuration(fromEnv)
	if err != nil {
		return err
	}

	cmd.Flags().Lookup(flagName).Changed = true
	*val = dur
	return nil
}

func loadStringFlagFromEnv(cmd *cobra.Command, flagName string, envVar string, val *string) error {
	if cmd.Flags().Lookup(flagName).Changed {
		return nil
	}

	fromEnv, ok := os.LookupEnv(envVar)
	if !ok {
		return nil
	}

	cmd.Flags().Lookup(flagName).Changed = true
	*val = fromEnv
	return nil
}

func updateDurationFromConfigProfile(profiles lib.Profiles, profile string, val *time.Duration) error {
	fromProfile, _, err := profiles.GetValue(profile, "assume_role_ttl")
	if err != nil {
		return nil
	}

	dur, err := time.ParseDuration(fromProfile)
	if err != nil {
		return err
	}

	*val = dur
	return nil
}

func execPre(cmd *cobra.Command, args []string) {
	if err := loadDurationFlagFromEnv(cmd, "session-ttl", "AWS_SESSION_TTL", &sessionTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_SESSION_TTL")
	}

	if err := loadDurationFlagFromEnv(cmd, "assume-role-ttl", "AWS_ASSUME_ROLE_TTL", &assumeRoleTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_ASSUME_ROLE_TTL")
	}
	if err := loadStringFlagFromEnv(cmd, "assume-role-arn", "AWS_ASSUME_ROLE_ARN", &assumeRoleARN); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_ASSUME_ROLE_ARN")
	}
}

func execRun(cmd *cobra.Command, args []string) error {
	dashIx := cmd.ArgsLenAtDash()
	if dashIx == -1 {
		return ErrCommandMissing
	}

	args, commandPart := args[:dashIx], args[dashIx:]
	if len(args) < 1 {
		return ErrTooFewArguments
	}

	if len(commandPart) == 0 {
		return ErrCommandMissing
	}

	profile := args[0]
	command := commandPart[0]

	var commandArgs []string
	if len(commandPart) > 1 {
		commandArgs = commandPart[1:]
	}

	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config. Use list command to see configured profiles.", profile)
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
		AssumeRoleArn:      assumeRoleARN,
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
				Set("command", "exec"),
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

	roleARN, err := p.GetRoleARNWithRegion(creds)
	if err != nil {
		return err
	}
	role := strings.Split(roleARN, "/")[1]

	env := environ(os.Environ())
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")
	env.Unset("AWS_OKTA_PROFILE")

	if region, ok := profiles[profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	env.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	env.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	env.Set("AWS_OKTA_PROFILE", profile)
	env.Set("AWS_OKTA_ASSUMED_ROLE_ARN", roleARN)
	env.Set("AWS_OKTA_ASSUMED_ROLE", role)

	if creds.SessionToken != "" {
		env.Set("AWS_SESSION_TOKEN", creds.SessionToken)
		env.Set("AWS_SECURITY_TOKEN", creds.SessionToken)
	}

	ecmd := exec.Command(command, commandArgs...)
	ecmd.Stdin = os.Stdin
	ecmd.Stdout = os.Stdout
	ecmd.Stderr = os.Stderr
	ecmd.Env = env

	// Forward SIGINT, SIGTERM, SIGKILL to the child command
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, os.Interrupt, os.Kill)

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

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
