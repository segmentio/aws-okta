package okta

import (
	"os/user"
	"path/filepath"
	"strings"

	"github.com/go-ini/ini"
)

type AwsConfig struct {
	Profiles map[string]map[string]string
	File     string
}

func NewAwsConfig() (config *AwsConfig, err error) {
	var usr *user.User
	usr, err = user.Current()
	if err != nil {
		return
	}

	homedir := usr.HomeDir
	config = &AwsConfig{
		File: filepath.Join(homedir, ".aws/config"),
	}

	return
}

func (a *AwsConfig) Load() (err error) {
	config, err := ini.Load(a.File)
	if err != nil {
		return
	}

	a.Profiles = make(map[string]map[string]string)

	for _, s := range config.Sections() {
		for _, k := range s.Keys() {
			pname := strings.TrimPrefix(s.Name(), "profile ")
			a.Profiles[pname] = map[string]string{k.Name(): k.Value()}
		}
	}
	return
}

func (a *AwsConfig) GetProfileArn(profile string) (arn string) {
	return a.Profiles[profile]["role_arn"]
}

func (a *AwsConfig) GetParentArn(profile string) (arn string) {
	return
}
