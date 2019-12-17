package configload

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/segmentio/aws-okta/profiles"
	log "github.com/sirupsen/logrus"

	"github.com/mitchellh/go-homedir"
	"github.com/vaughan0/go-ini"
)

type config interface {
	Parse() (profiles.Profiles, error)
}

type fileConfig struct {
	file string
}

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

func (c *fileConfig) Parse() (profiles.Profiles, error) {
	if c.file == "" {
		return nil, nil
	}

	log.Debugf("Parsing config file %s", c.file)
	f, err := ini.LoadFile(c.file)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file %q: %v", c.file, err)
	}

	ps := profiles.Profiles{"okta": map[string]string{}}
	for sectionName, section := range f {
		ps[strings.TrimPrefix(sectionName, "profile ")] = section
	}

	return ps, nil
}
