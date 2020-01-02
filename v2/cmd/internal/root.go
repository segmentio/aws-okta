package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"github.com/segmentio/aws-okta/v2/cmd/internal/analytics"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	FlagKeyringBackend string
	FlagDebug          bool
	FlagAWSRegion      string
)

var (
	Analytics analytics.Client
	Version   string
)

var RootCmd = &cobra.Command{
	Use:          "aws-okta",
	Short:        "aws-okta allows you to authenticate with AWS using your okta credentials",
	SilenceUsage: true,
	// TODO(nick): not sure what this does
	SilenceErrors:     true,
	PersistentPreRun:  prerun,
	PersistentPostRun: postrun,
}

type ErrBadArgCount struct {
	Actual   int
	Expected int
}

func (e *ErrBadArgCount) Error() string {
	return fmt.Sprintf("wrong number of arguments; expected %d, got %d", e.Expected, e.Actual)
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string, writeKey string) {
	Version = version
	if writeKey != "" {
		Analytics = analytics.New(writeKey)
		Analytics.UserId = os.Getenv("USER")
		Analytics.Version = Version
	}
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		if errors.Is(err, &ErrBadArgCount{}) {
			RootCmd.Usage()
		}
		os.Exit(1)
	}
}

func prerun(cmd *cobra.Command, args []string) {
	// Load backend from env var if not set as a flag
	// TODO(nick): this is stupid; wurely there's a lib for this
	if !cmd.Flags().Lookup("backend").Changed {
		backendFromEnv, ok := os.LookupEnv("AWS_OKTA_BACKEND")
		if ok {
			FlagKeyringBackend = backendFromEnv
		}
	}

	Analytics.KeyringBackend = FlagKeyringBackend

	if FlagDebug {
		log.SetLevel(log.DebugLevel)
	}

	Analytics.Identify()
}

func postrun(cmd *cobra.Command, args []string) {
	Analytics.Close()
}

func init() {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	RootCmd.PersistentFlags().StringVarP(&FlagKeyringBackend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&FlagDebug, "debug", "d", false, "Enable debug logging")
	RootCmd.PersistentFlags().StringVarP(&FlagAWSRegion, "aws-region", "r", "us-east-1", "AWS region")
}
