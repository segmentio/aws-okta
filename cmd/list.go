package cmd

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List aws profiles available",
	Example: " aws-keycloak list",
	RunE:    runList,
}

func init() {
	RootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return ErrTooManyArguments
	}
	roles, err := listRoles()
	if err != nil {
		return err
	}

	re := regexp.MustCompile("role/keycloak-([^/]+)$")
	for _, role := range roles {
		p := re.FindStringSubmatch(role)
		fmt.Printf("%-65s %s\n", role, p[1])
	}

	return nil
}
