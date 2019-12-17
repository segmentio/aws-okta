package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/cmd/configload"
	"github.com/segmentio/aws-okta/profiles"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list will show you the profiles currently configured",
	RunE:  listRun,
}

func init() {
	RootCmd.AddCommand(listCmd)
}

// TODO(nick): mv lib.Profiles from lib into cmd

func listProfiles() (profiles.Profiles, error) {
	config, err := configload.NewConfigFromEnv()
	if err != nil {
		return nil, err
	}

	profiles, err := config.Parse()
	if err != nil {
		return nil, err
	}

	return profiles, nil
}

// TODO(nick): mv lib.Profiles from lib into cmd
func listProfileNames(ps profiles.Profiles) []string {
	// Let's sort this list of profiles so we can have some more deterministic output:
	var profileNames []string

	for profile := range ps {
		profileNames = append(profileNames, profile)
	}

	sort.Strings(profileNames)

	return profileNames
}

func listRun(cmd *cobra.Command, args []string) error {
	profiles, err := listProfiles()
	if err != nil {
		return err
	}

	profileNames := listProfileNames(profiles)

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', 0)
	fmt.Fprintln(w, "PROFILE\tARN\tSOURCE_ROLE\t")
	for _, profile := range profileNames {
		v := profiles[profile]
		if role, exist := v["role_arn"]; exist {
			fmt.Fprintf(w, "%s\t%s\t%s\n", profile, role, v["source_profile"])
		}
	}
	w.Flush()

	if analyticsEnabled && analyticsClient != nil {
		analyticsClient.Enqueue(analytics.Track{
			UserId: username,
			Event:  "Listed Profiles",
			Properties: analytics.NewProperties().
				Set("backend", backend).
				Set("aws-okta-version", version).
				Set("profile-count", len(profiles)).
				Set("command", "list"),
		})
	}
	return nil
}
