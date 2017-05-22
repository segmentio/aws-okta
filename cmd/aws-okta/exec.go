package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/99designs/aws-vault/keyring"
	okta "github.com/segmentio/aws-okta"
	"github.com/segmentio/conf"
)

type execConfig struct {
	Debug   bool   `conf:"debug" help:"Enable debug for the Exec command"`
	Profile string `conf:"profile" help:"AWS Profile to use to exec the command."`
}

func cmdExec(args []string, execSig chan os.Signal) (err error) {
	var awsConfig *okta.AwsConfig

	config := execConfig{}
	_, command := conf.LoadWith(&config, conf.Loader{
		Name: "aws-okta exec",
		Args: args,
	})

	awsConfig, err = okta.NewAwsConfig()
	awsConfig.Load()

	roleArn := awsConfig.GetProfileArn(config.Profile)
	if roleArn == "" {
		err = fmt.Errorf("%s profile not found in AWS configuration", config.Profile)
		return
	}

	//TODO: Should be in keystore.go
	// Retrive login from keystore
	var k keyring.Keyring
	k, err = keyring.Open(okta.KeystoreName, "file")
	if err != nil {
		return
	}

	var i keyring.Item
	i, err = k.Get(okta.KeystoreOktaKey)
	if err != nil {
		return
	}
	var login okta.OktaUser
	err = json.Unmarshal(i.Data, &login)
	if err != nil {
		return
	}

	client := okta.NewOktaClient(
		okta.OktaOrganization,
		login.Username,
		login.Password,
	)

	err = client.Authenticate(roleArn, config.Profile)
	if err != nil {
		return
	}

	env := environ(os.Environ())
	env.Set("AWS_ACCESS_KEY_ID", client.AccessKeyId)
	env.Set("AWS_SECRET_ACCESS_KEY", client.SecretAccessKey)
	env.Set("AWS_SESSION_TOKEN", client.SessionToken)
	env.Set("AWS_SECURITY_TOKEN", client.SessionToken)

	signal.Notify(execSig, os.Interrupt, os.Kill)

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go func() {
		sig := <-execSig
		if cmd.Process != nil {
			cmd.Process.Signal(sig)
		}
	}()

	var waitStatus syscall.WaitStatus
	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			os.Exit(waitStatus.ExitStatus())
		}
		if err != nil {
			panic(err)
		}
	}

	return
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
