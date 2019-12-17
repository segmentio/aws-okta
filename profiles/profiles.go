// TODO: move this package under cmd, and remove all references in lib
package profiles

import "fmt"

func SourceProfile(p string, from Profiles) string {
	return sourceProfile(p, from)
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

type Profiles map[string]map[string]string

func (p Profiles) GetValue(profile string, config_key string) (string, string, error) {
	config_value, ok := p[profile][config_key]
	if ok {
		return config_value, profile, nil
	}

	// Lookup from the `source_profile`, if it exists
	profile, ok = p[profile]["source_profile"]
	if ok {
		config_value, ok := p[profile][config_key]
		if ok {
			return config_value, profile, nil
		}

	}

	// Fallback to `okta` if no profile supplies the value
	profile = "okta"
	config_value, ok = p[profile][config_key]
	if ok {
		return config_value, profile, nil
	}

	return "", "", fmt.Errorf("Could not find %s in %s, source profile, or okta", config_key, profile)
}
