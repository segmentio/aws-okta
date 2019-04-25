package provider

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	homedir "github.com/mitchellh/go-homedir"
	ini "github.com/vaughan0/go-ini"
)

type sections ini.File

type config interface {
	Parse() (sections, error)
}

type fileConfig struct {
	file string
}

const (
	DefaultEnv  = "KEYCLOAK_CONFIG_FILE"
	DefaultConf = "/.aws/keycloak-config"
)

func EnvFileOrDefault() (string, error) {
	file := os.Getenv(DefaultEnv)
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, DefaultConf)
	}
	return file, nil
}

func NewConfigFromFile(file string) (config, error) {
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	return &fileConfig{file: file}, nil
}

func (c *fileConfig) Parse() (sections, error) {
	if c.file == "" {
		return nil, nil
	}

	log.Debugf("Parsing config file %s", c.file)
	f, err := ini.LoadFile(c.file)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file %q: %v", c.file, err)
	}

	return sections(f), nil
}
