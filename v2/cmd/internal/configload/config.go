// TODO: overhaul
package configload

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/mitchellh/go-homedir"
	"github.com/vaughan0/go-ini"
)

type fileConfig struct {
	file string
}

func FindAndParse() (Profiles, error) {
	c, err := NewFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to load profiles from config: %w", err)
	}

	return c.Parse()
}

func NewFromEnv() (*fileConfig, error) {
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

	ps := Profiles{"okta": Profile{}}
	for sectionName, section := range f {
		// TODO: types
		ps[strings.TrimPrefix(sectionName, "profile ")] = Profile(section)
	}

	return ps, nil
}

type ErrNotFound struct {
	Profile       string
	Key           string
	SourceProfile string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("key '%s' not found in profile '%s', or source profile '%s', or base profile 'okta'", e.Key, e.Profile, e.SourceProfile)
}

type Profile map[string]string

type Profiles map[string]Profile

func (p Profiles) Get(profileName string, key string) (value string, err error) {
	value, ok := p[profileName][key]
	if ok {
		return
	}

	// Lookup from the `source_profile`, if it exists
	sourceProfile, ok := p[profileName]["source_profile"]
	if ok {
		value, ok = p[sourceProfile][key]
		if ok {
			return
		}

	}

	// Fallback to `okta` if no profile supplies the value
	value, ok = p["okta"][key]
	if ok {
		return
	}

	return "", &ErrNotFound{
		Profile:       profileName,
		Key:           key,
		SourceProfile: sourceProfile,
	}
}

func (p Profiles) GetWithDefault(profileName string, key string, defaultValue string) string {
	v, err := p.Get(profileName, key)
	if err != nil {
		return defaultValue
	}
	return v
}
