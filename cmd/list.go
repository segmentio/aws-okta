package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	analytics "github.com/segmentio/analytics-go"
	"github.com/segmentio/aws-okta/lib"
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

func listRun(cmd *cobra.Command, args []string) error {
	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 8, 2, '\t', 0)
	fmt.Fprintln(w, "profile\tarn\tsource_role\t")
	fmt.Fprintln(w, "---\t---\t---\t")
	for profile, v := range profiles {
		if role, exist := v["role_arn"]; exist {
			if src, exist := v["source_profile"]; exist {
				s := fmt.Sprintf("%s\t%s\t%s\t", profile, role, src)
				fmt.Fprintln(w, s)
			}
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
