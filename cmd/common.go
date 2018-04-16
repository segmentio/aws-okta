package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"

	"github.com/mulesoft-labs/aws-keycloak/provider"
)

/**
 * Appends AWS env vars to existing env
 */
func runWithAwsEnv(name string, arg ...string) error {
	k, err := provider.NewKeycloakProvider(kr, kcprofile, section)
	if err != nil {
		return err
	}
	a := &provider.AwsProvider{
		Keyring: kr,
	}
	p := provider.Provider{
		A: a,
		K: k,
	}

	stscreds, _, err := p.Retrieve(awsrole)
	if err != nil {
		return err
	}

	env := []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", *stscreds.AccessKeyId),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", *stscreds.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", *stscreds.SessionToken),
	}
	if region, found := os.LookupEnv("AWS_DEFAULT_REGION"); found {
		env = append(env, fmt.Sprintf("AWS_DEFAULT_REGION=%s", region))
	}

	log.Debugf("Running command `%s %s` with AWS env vars set", name, strings.Join(arg, " "))
	return runWithEnv(name, append(os.Environ(), env...), arg...)

}

func runWithEnv(name string, env []string, arg ...string) error {
	binary, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("Error finding `%s`. Is it installed and in your PATH? %s", name, err)
	}

	cmd := exec.Command(binary, arg...)
	cmd.Env = env

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	return err
}
