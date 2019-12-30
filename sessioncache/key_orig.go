package sessioncache

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type OrigKey struct {
	ProfileName string
	ProfileConf map[string]string
	Duration    time.Duration
}

// Key returns a key for the keyring item. This is a string containing the source profile name,
// the profile name, and a hash of the duration
//
// this is a copy of KeyringSessions.key and should preserve behavior, *except* that it assumes `profileName`
// is a valid and existing profile name
func (k OrigKey) Key() string {
	// nick: I don't understand this at all. This key function is roughly:
	// sourceProfileName + hex(md5(duration + json(profileConf)))
	// - why md5?
	// - why the JSON of the whole profile? (especially strange considering JSON map order is undetermined)
	// TODO(nick): document this
	var source string
	if source = k.ProfileConf["source_profile"]; source == "" {
		source = k.ProfileName
	}
	hasher := md5.New()
	hasher.Write([]byte(k.Duration.String()))

	enc := json.NewEncoder(hasher)
	enc.Encode(k.ProfileConf)

	return fmt.Sprintf("%s session (%x)", source, hex.EncodeToString(hasher.Sum(nil))[0:10])
}
