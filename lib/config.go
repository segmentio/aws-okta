package lib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/mitchellh/go-homedir"
	"github.com/vaughan0/go-ini"
)

type Profiles map[string]map[string]string

type config interface {
	Parse() (Profiles, error)
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

func (c *fileConfig) Parse() (Profiles, error) {
	if c.file == "" {
		return nil, nil
	}

	log.Debugf("Parsing config file %s", c.file)
	f, err := ini.LoadFile(c.file)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file %q: %v", c.file, err)
	}

	profiles := Profiles{"okta": map[string]string{}}
	for sectionName, section := range f {
		profiles[strings.TrimPrefix(sectionName, "profile ")] = section
	}

	return profiles, nil
}

// sourceProfile returns either the defined source_profile or p if none exists
func sourceProfile(p string, from Profiles) string {
	if conf, ok := from[p]; ok {
		if source := conf["source_profile"]; source != "" {
			return source
		}
	}
	return p
}

// GetDirectValue looks for the given setting directly set in the specified
// profile. Unlike GetValue, it does not descend into `search_profile` or
// fallback to the `okta` profile.
func (p Profiles) GetDirectValue(profile string, config_key string) (string, string, error) {
	config_value, ok := p[profile][config_key]
	if ok {
		return config_value, profile, nil
	}

	return "", "", fmt.Errorf("Could not find %s in profile %s", config_key, profile)
}

// GetValue looks for the given setting in the profile specified, its
// `source_profile` (if set), and the `okta` profile, in that order. If found,
// the corresponding value is returned. Otherwise, an error is returned.
func (p Profiles) GetValue(profile string, config_key string) (string, string, error) {
	if config_value, profile, err := p.GetDirectValue(profile, config_key); err == nil {
		return config_value, profile, nil
	}

	// If a `source_profile` is set, check it too
	var ok bool
	profile, ok = p[profile]["source_profile"]
	if ok {
		if config_value, profile, err := p.GetDirectValue(profile, config_key); err == nil {
			return config_value, profile, nil
		}
	}

	// Fallback to the `okta` profile
	if config_value, profile, err := p.GetDirectValue("okta", config_key); err == nil {
		return config_value, profile, nil
	}

	return "", "", fmt.Errorf("Could not find %s in %s, source profile, or okta", config_key, profile)
}
