package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/lib"
	"github.com/spf13/cobra"
)

var (
	sessionTTL    time.Duration
	assumeRoleTTL time.Duration
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec <profile> -- <command>",
	Short: "exec will run the command specified with aws credentials set in the environment",
	RunE:  execRun,
}

func init() {
	RootCmd.AddCommand(execCmd)
	execCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	execCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Minute*15, "Expiration time for assumed role")
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

	env := environ(os.Environ())
	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")

	if region, ok := profiles[profile]["region"]; ok {
		env.Set("AWS_DEFAULT_REGION", region)
		env.Set("AWS_REGION", region)
	}

	env.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	env.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)

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
