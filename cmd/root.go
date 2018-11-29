package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Errors returned from frontend commands
var (
	ErrCommandMissing              = errors.New("must specify command to run")
	ErrTooManyArguments            = errors.New("too many arguments")
	ErrTooFewArguments             = errors.New("too few arguments")
	ErrFailedToSetCredentials      = errors.New("Failed to set credentials in your keyring")
	ErrFailedToValidateCredentials = errors.New("Failed to validate credentials")
)

const (
	// keep expected behavior pre-u2f with duo push
	DefaultMFADevice = "phone1"
)

// global flags
var (
	backend           string
	mfaDevice         string
	debug             bool
	version           string
	analyticsWriteKey string
	analyticsEnabled  bool
	analyticsClient   analytics.Client
	username          string
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:               "aws-okta",
	Short:             "aws-okta allows you to authenticate with AWS using your okta credentials",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRun:  prerun,
	PersistentPostRun: postrun,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(vers string, writeKey string) {
	version = vers
	analyticsWriteKey = writeKey
	analyticsEnabled = analyticsWriteKey != ""
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

	if !cmd.Flags().Lookup("mfa-device").Changed {
		mfaDeviceFromEnv, ok := os.LookupEnv("AWS_OKTA_MFA_DEVICE")
		if ok {
			mfaDevice = mfaDeviceFromEnv
		} else {
			mfaDevice = DefaultMFADevice
		}
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	if analyticsEnabled {
		// set up analytics client
		analyticsClient, _ = analytics.NewWithConfig(analyticsWriteKey, analytics.Config{
			BatchSize: 1,
		})

		username = os.Getenv("USER")
		analyticsClient.Enqueue(analytics.Identify{
			UserId: username,
			Traits: analytics.NewTraits().
				Set("aws-okta-version", version),
		})
	}
}

func postrun(cmd *cobra.Command, args []string) {
	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Close()
	}
}

func init() {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}
	RootCmd.PersistentFlags().StringVarP(&mfaDevice, "mfa-device", "m", "phone1", "Device to use phone1, phone2, u2f or token")
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
}
