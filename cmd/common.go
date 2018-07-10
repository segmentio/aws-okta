package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/mulesoft-labs/aws-keycloak/provider"
)

func makeProvider() (*provider.Provider, error) {
	k, err := provider.NewKeycloakProvider(kr, kcprofile, kcConf)
	if err != nil {
		return nil, err
	}
	if region == "" {
		if v, e := kcConf["default_region"]; e {
			region = v
		} else {
			region = provider.DefaultRegion
		}
	}
	a := &provider.AwsProvider{
		Keyring: kr,
		Region:  region,
	}
	return &provider.Provider{
		A: a,
		K: k,
	}, nil
}

func getAwsStsCreds() (sts.Credentials, error) {
	p, err := makeProvider()
	if err != nil {
		return sts.Credentials{}, err
	}
	stscreds, _, err := p.Retrieve(awsrole)
	return stscreds, err
}

func listRoles() ([]string, error) {
	p, err := makeProvider()
	if err != nil {
		return []string{}, err
	}
	return p.List()
}

/**
 * Appends AWS env vars to existing env
 */
func runWithAwsEnv(name string, arg ...string) error {
	stscreds, err := getAwsStsCreds()
	if err != nil {
		return err
	}

	env := []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", *stscreds.AccessKeyId),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", *stscreds.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", *stscreds.SessionToken),
	}
	if region != "" {
		env = append(env, fmt.Sprintf("AWS_DEFAULT_REGION=%s", region))
		env = append(env, fmt.Sprintf("AWS_REGION=%s", region))
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
	cmd.Stdin = os.Stdin

	err = cmd.Run()
	return err
}
