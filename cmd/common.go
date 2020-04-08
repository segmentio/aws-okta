package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"

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
func runWithAwsEnv(includeFullEnv bool, name string, arg ...string) error {
	stscreds, err := getAwsStsCreds()
	if err != nil {
		return err
	}

	env := []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", *stscreds.AccessKeyId),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", *stscreds.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", *stscreds.SessionToken),
		fmt.Sprintf("AWS_KEYCLOAK_PROFILE=%s", awsrole),
	}
	if region != "" {
		env = append(env, fmt.Sprintf("AWS_DEFAULT_REGION=%s", region))
		env = append(env, fmt.Sprintf("AWS_REGION=%s", region))
	}

	log.Debugf("Running command `%s %s` with AWS env vars set", name, strings.Join(arg, " "))
	if includeFullEnv {
		env = append(os.Environ(), env...)
	}
	return runWithEnv(name, env, arg...)
}

/**
 * This method will only return if there is an erorr running the subcommand.
 * Otherwise it will Exit with the appropriate exit code.
 */
func runWithEnv(name string, env []string, arg ...string) error {
	binary, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("Error finding `%s`. Is it installed and in your PATH? %s", name, err)
	}

	cmd := exec.Command(binary, arg...)
	cmd.Env = env

	writer, _ := cmd.StdinPipe()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	errChan := make(chan error, 1)
	go func() {
		defer writer.Close()
		stdin := bufio.NewReader(os.Stdin)
		for {
			input, err := stdin.ReadByte()
			if err == io.EOF {
				errChan <- nil
				break
			}
			if err == nil {
				_, err = writer.Write([]byte{input})
			}
			if err != nil {
				errChan <- err
				break
			}
		}
	}()

	// This is subtly different from simply `cmd.Run()`, though I don't understand why.
	err = cmd.Start()
	if err != nil {
		return err
	}
	err = cmd.Wait()

	writer.Close()
	close(errChan)

	readErr := <-errChan
	if readErr != nil {
		os.Stderr.WriteString(readErr.Error())
		os.Exit(1)
	}

	if err == nil {
		os.Exit(0)
	}

	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ProcessState.ExitCode())
	}

	return err
}
