package main

import (
	"time"

	"encoding/json"

	"github.com/99designs/aws-vault/keyring"
	"github.com/apex/log"
	"github.com/aws/aws-sdk-go/service/sts"
	okta "github.com/segmentio/aws-okta"
	"github.com/segmentio/conf"
)

type infoConfig struct {
	Profile string `conf:"profile" help:"AWS Profile to use to exec the command."`
}

func cmdInfo(args []string) (err error) {
	var creds sts.Credentials

	config := loginConfig{}
	_, _ = conf.LoadWith(&config, conf.Loader{
		Name: "aws-okta info",
		Args: args,
	})

	var k keyring.Keyring
	k, err = keyring.Open(okta.KeystoreName, "file")
	if err != nil {
		return
	}

	var i keyring.Item
	i, err = k.Get(config.Profile)
	if err != nil {
		return
	}

	err = json.Unmarshal(i.Data, &creds)
	if err != nil {
		return
	}

	logger := log.WithFields(log.Fields{
		"AccessKeyId": *creds.AccessKeyId,
		"Expiration":  creds.Expiration,
	})

	if creds.Expiration.Before(time.Now()) {
		logger.Info("current session is expired")
	} else {
		logger.Info("current session is valid")
	}

	return
}
