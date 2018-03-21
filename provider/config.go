package provider

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
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
	defaultConf = "/.aws/keycloak-config"
)

func EnvFileOrDefault(envFile string) (string, error) {
	file := os.Getenv(envFile)
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, defaultConf)
	}
	return file, nil
}

func NewConfigFromFile(file string) (config, error) {
	if _, err := os.Stat(file); err != nil {
		return nil, err
	}
	return &fileConfig{file: file}, nil
}

/*
func NewConfigFromEnv() (config, error) {
	file := os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return nil, err
		}
		file = filepath.Join(home, "/.aws/config")
		if _, err := os.Stat(file); os.IsNotExist(err) {
			file = ""
		}
	}
	return &fileConfig{file: file}, nil
}
*/

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

/*
// sourceProfile returns either the defined source_profile or p if none exists
func sourceProfile(p string, from profiles) string {
	if conf, ok := from[p]; ok {
		if source := conf["source_profile"]; source != "" {
			return source
		}
	}
	return p
}
*/
