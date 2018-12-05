package cmd

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
)

var (
	eachFilter string
)

var eachCmd = &cobra.Command{
	Use:     "each",
	Short:   "Run the command for each matching profile available to you",
	Example: " aws-keycloak each -- aws iam list-account-aliases",
	RunE:    runEach,
}

func init() {
	eachCmd.PersistentFlags().StringVarP(&listFilter, "filter", "f", "", "Regex to filter listed roles (eg. 'admin')")
	RootCmd.AddCommand(eachCmd)
}

func runEach(cmd *cobra.Command, args []string) error {
	filter, err := regexp.Compile(eachFilter)
	if err != nil {
		return err
	}

	roles, err := listRoles()
	if err != nil {
		return err
	}

	re := regexp.MustCompile("role/keycloak-([^/]+)$")
	for _, role := range roles {
		if !filter.MatchString(role) {
			continue
		}
		p := re.FindStringSubmatch(role)
		fmt.Printf("%s\n", p[1])
		awsrole = p[1]
		runWithAwsEnv(true, args[0], args[1:]...)
	}

	return nil
}
