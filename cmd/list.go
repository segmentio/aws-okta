package cmd

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
)

var (
	listFilter string
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List aws profiles available",
	Example: " aws-keycloak list",
	RunE:    runList,
}

func init() {
	listCmd.PersistentFlags().StringVarP(&listFilter, "filter", "f", "", "Regex to filter listed roles (eg. 'admin')")
	RootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return ErrTooManyArguments
	}

	filter, err := regexp.Compile(listFilter)
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
		fmt.Printf("%-65s %s\n", role, p[1])
	}

	return nil
}
