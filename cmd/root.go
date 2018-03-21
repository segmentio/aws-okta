package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/mulesoft-labs/aws-keycloak/lib"
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
	backend   string
	kr        keyring.Keyring
	debug     bool
	kcprofile string
	awsrole   string
	section   map[string]string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:               "aws-keycloak",
	Short:             "aws-keycloak allows you to authenticate with AWS using your keycloak credentials",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRunE: prerun,
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
	}

	// Load backend from env var if not set as a flag
	if !cmd.Flags().Lookup("backend").Changed {
		backendFromEnv, ok := os.LookupEnv("AWS_KEYCLOAK_BACKEND")
		if ok {
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

	configFile, err := lib.EnvFileOrDefault("KEYCLOAK_CONFIG_FILE")
	if err != nil {
		return err
	}

	config, err := lib.NewConfigFromFile(configFile)
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
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	RootCmd.PersistentFlags().StringVarP(&kcprofile, "keycloak-profile", "k", "id", "Keycloak system to auth to")
	RootCmd.PersistentFlags().StringVarP(&awsrole, "profile", "p", "", "AWS profile to run against (optional)")
}
