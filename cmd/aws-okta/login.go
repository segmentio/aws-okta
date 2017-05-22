package main

import (
	"fmt"

	"encoding/json"

	"github.com/99designs/aws-vault/keyring"
	"github.com/apex/log"
	"github.com/aws/aws-sdk-go/service/sts"
	okta "github.com/segmentio/aws-okta"
	"github.com/segmentio/conf"
)

type loginConfig struct {
	Profile string `conf:"profile" help:"AWS Profile to use to exec the command."`
}

func cmdLogin(args []string) (err error) {
	var awsConfig *okta.AwsConfig
	var username string
	var password string
	var creds sts.Credentials

	config := loginConfig{}
	_, _ = conf.LoadWith(&config, conf.Loader{
		Name: "aws-okta login",
		Args: args,
	})

	// Ask username password from prompt
	username, err = okta.Prompt("Okta username", false)
	password, err = okta.Prompt("Okta password", true)
	if err != nil {
		return
	}
	fmt.Println()

	// Test authentication
	awsConfig, err = okta.NewAwsConfig()
	awsConfig.Load()

	roleArn := awsConfig.GetProfileArn(config.Profile)
	if roleArn == "" {
		err = fmt.Errorf("%s profile not found in AWS configuration", config.Profile)
		return
	}

	client := okta.NewOktaClient(
		okta.OktaOrganization,
		username,
		password,
	)

	err = client.Authenticate(roleArn, config.Profile)
	if err != nil {
		return
	}

	// Store data into keystore
	creds, _ = client.GetCredentials()

	log.WithFields(log.Fields{
		"credentials": creds,
	}).Debug("retrieved credentials")

	err = StoreBlob(config.Profile, creds)

	// Store Okta username/password to keystore
	usr := &okta.OktaUser{
		Username: username,
		Password: password,
	}
	err = StoreBlob(okta.KeystoreOktaKey, usr)

	return
}

func StoreBlob(key string, data interface{}) (err error) {
	var k keyring.Keyring
	var j []byte
	j, err = json.Marshal(data)
	if err != nil {
		return
	}

	k, err = keyring.Open(okta.KeystoreName, "file")
	if err != nil {
		return
	}

	err = k.Set(keyring.Item{
		Key:  key,
		Data: j,
	})

	return
}
