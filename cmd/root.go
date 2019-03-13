package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/99designs/keyring"
	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
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

// if non-zero, will log TLS keys to this file
var UseTLSKeyLogFile = "yes"

// SSL to be consistent with other producers, like Firefox and Chrome
const TLSKeyLogFileEnv = "SSLKEYLOGFILE"

const (
	// keep expected behavior pre-u2f with duo push
	DefaultMFADuoDevice = "phone1"
)

// global flags
var (
	backend           string
	mfaConfig         lib.MFAConfig
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

// addTLSKeyLog opens a TLS keylog and add its to oktaClient. Its return value
// should be closed by the caller (if it isn't nil)
func addTLSKeyLog(oktaClient *lib.OktaClient) (w io.WriteCloser) {
	if UseTLSKeyLogFile != "" {
		file := os.Getenv(TLSKeyLogFileEnv)
		if file != "" {
			w, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				log.Debugf("Failed to open TLS key log file %s: %s", file, err)
			} else {
				log.Infof("SECURITY WARNING: logging TLS keys to %s", file)
				oktaClient.TLSKeyLogWriter = w
			}
		}
	}
	return w
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
	RootCmd.PersistentFlags().StringVarP(&mfaConfig.Provider, "mfa-provider", "", "", "MFA Provider to use (eg DUO, OKTA, GOOGLE)")
	RootCmd.PersistentFlags().StringVarP(&mfaConfig.FactorType, "mfa-factor-type", "", "", "MFA Factor Type to use (eg push, token:software:totp)")
	RootCmd.PersistentFlags().StringVarP(&mfaConfig.DuoDevice, "mfa-duo-device", "", "phone1", "Device to use phone1, phone2, u2f or token")
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
}

func updateMfaConfig(cmd *cobra.Command, profiles lib.Profiles, profile string, config *lib.MFAConfig) {
	if !cmd.Flags().Lookup("mfa-duo-device").Changed {
		mfaDeviceFromEnv, ok := os.LookupEnv("AWS_OKTA_MFA_DUO_DEVICE")
		if ok {
			config.DuoDevice = mfaDeviceFromEnv
		} else {
			config.DuoDevice = DefaultMFADuoDevice
		}
	}

	if !cmd.Flags().Lookup("mfa-provider").Changed {
		mfaProvider, ok := os.LookupEnv("AWS_OKTA_MFA_PROVIDER")
		if ok {
			config.Provider = mfaProvider
		} else {
			mfaProvider, _, err := profiles.GetValue(profile, "mfa_provider")
			if err == nil {
				config.Provider = mfaProvider
			}
		}
	}

	if !cmd.Flags().Lookup("mfa-factor-type").Changed {
		mfaFactorType, ok := os.LookupEnv("AWS_OKTA_MFA_FACTOR_TYPE")
		if ok {
			config.FactorType = mfaFactorType
		} else {
			mfaFactorType, _, err := profiles.GetValue(profile, "mfa_factor_type")
			if err == nil {
				config.FactorType = mfaFactorType
			}
		}
	}
}
