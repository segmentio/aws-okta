package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
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
	backend string
	debug   bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:              "aws-okta",
	Short:            "aws-okta allows you to authenticate with AWS using your okta credentials",
	SilenceUsage:     true,
	SilenceErrors:    true,
	PersistentPreRun: prerun,
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

func prerun(cmd *cobra.Command, args []string) {
	// Load backend from env var if not set as a flag
	if !cmd.Flags().Lookup("backend").Changed {
		backendFromEnv, ok := os.LookupEnv("AWS_OKTA_BACKEND")
		if ok {
			backend = backendFromEnv
		}
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", keyring.DefaultBackend, fmt.Sprintf("Secret backend to use %s", keyring.SupportedBackends()))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
}
