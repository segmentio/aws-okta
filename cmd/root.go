package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/mulesoft-labs/aws-keycloak/provider"
)

// Errors returned from frontend commands
var (
	ErrCommandMissing         = errors.New("must specify command to run")
	ErrTooManyArguments       = errors.New("too many arguments")
	ErrTooFewArguments        = errors.New("too few arguments")
	ErrFailedToSetCredentials = errors.New("Failed to set credentials in your keyring")
)

// global flags
var (
	backend    string
	kr         keyring.Keyring
	debug      bool
	configFile string
	kcprofile  string
	awsrole    string
	section    map[string]string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:               "aws-keycloak [flags] -- <aws command>",
	Short:             "aws-keycloak allows you to authenticate with AWS using your keycloak credentials",
	Example:           "  aws-keycloak -p power-devx -- sts get-caller-identity",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRunE: prerun,
	RunE:              executeAwsCmd,
	Version:           "1.0.2-beta",
}

func executeAwsCmd(cmd *cobra.Command, args []string) error {
	k, err := provider.NewKeycloakProvider(kr, kcprofile, section)
	if err != nil {
		return err
	}
	a := &provider.AwsProvider{
		Keyring: kr,
	}
	p := provider.Provider{
		A: a,
		K: k,
	}

	stscreds, awsshortrole, err := p.Retrieve(awsrole)
	if err != nil {
		return err
	}

	awsenv := []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", *stscreds.AccessKeyId),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", *stscreds.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", *stscreds.SessionToken),
	}
	if region, found := os.LookupEnv("AWS_DEFAULT_REGION"); found {
		awsenv = append(awsenv, fmt.Sprintf("AWS_DEFAULT_REGION=%s", region))
	}
	awsprofileenv := fmt.Sprintf("AWS_PROFILE=%s", awsshortrole)

	stderr, runErr := runAwsCommand(append(awsenv, awsprofileenv), args...)
	if runErr != nil {
		if _, ok := runErr.(*exec.ExitError); ok {
			errStr := fmt.Sprintf("The config profile (%s) could not be found", awsshortrole)
			if strings.Contains(stderr, errStr) {
				// Command used `-p`, but there isn't any aws config for that.
				// Explain and run anyway.
				log.Warnf("--profile argument expects aws config to already exist so it can use the default region.")
				log.Warnf("Use `aws configure --profile %s`", awsshortrole)
				log.Warnf("  but leave Access Key and Secret blank.")
				log.Warnf("Continuing without aws profile.")
				stderr, runErr = runAwsCommand(awsenv, args...)
			}
		}
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, stderr)
	}

	return runErr
}

// Always returns stderr as a string as well as any errors
func runAwsCommand(env []string, arg ...string) (string, error) {
	aws_binary, err := exec.LookPath("aws")
	if err != nil {
		return "", fmt.Errorf("Error finding `aws`. Is it installed and in your PATH? %s", err)
	}

	awscmd := exec.Command(aws_binary, arg...)
	awscmd.Env = env

	awscmd.Stdout = os.Stdout
	//awscmd.Stderr = os.Stderr
	var stderr bytes.Buffer
	awscmd.Stderr = &stderr

	runErr := awscmd.Run()
	return stderr.String(), runErr
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		switch err {
		case ErrTooFewArguments, ErrTooManyArguments:
			RootCmd.Usage()
		}
		os.Exit(1)
	}
}

func prerun(cmd *cobra.Command, args []string) error {
	if debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	if cmd.Name() == "help" {
		return nil
	}

	// Load backend from env var if not set as a flag
	if !cmd.Flags().Lookup("backend").Changed {
		if backendFromEnv, ok := os.LookupEnv("AWS_KEYCLOAK_BACKEND"); ok {
			backend = backendFromEnv
		}
	}

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	ring, err := keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		ServiceName:              "keycloak-login",
		LibSecretCollectionName:  "awsvault",
	})
	kr = ring
	if err != nil {
		return err
	}

	if !cmd.Flags().Lookup("config").Changed {
		configFile, err = provider.EnvFileOrDefault()
		if err != nil {
			return err
		}
	}

	config, err := provider.NewConfigFromFile(configFile)
	if err != nil {
		return err
	}

	sections, err := config.Parse()
	if err != nil {
		return err
	}
	section = sections[kcprofile]
	if len(section) == 0 {
		return fmt.Errorf("No keycloak profile found at %s", kcprofile)
	}

	return nil
}

func init() {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}
	RootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", provider.DefaultConf, "Keycloak provider configuration")
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	RootCmd.PersistentFlags().StringVarP(&kcprofile, "keycloak-profile", "k", provider.DefaultSection, "Keycloak system to auth to")
	RootCmd.PersistentFlags().StringVarP(&awsrole, "profile", "p", "", "AWS profile to run against (optional)")
}
