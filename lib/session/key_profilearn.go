package session

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type KeyWithProfileARN struct {
	ProfileName string
	ProfileConf map[string]string
	Duration    time.Duration
	ProfileARN  string
}

// Key returns a key for the keyring item. For all purposes it behaves the same way as
// OrigKey but also takes the ProfileARN into account when generating the key value.
func (k KeyWithProfileARN) Key() string {
	var source string
	if source = k.ProfileConf["source_profile"]; source == "" {
		source = k.ProfileName
	}
	hasher := md5.New()
	hasher.Write([]byte(k.Duration.String()))
	hasher.Write([]byte(k.ProfileARN))

	enc := json.NewEncoder(hasher)
	enc.Encode(k.ProfileConf)

	return fmt.Sprintf("%s session (%x)", source, hex.EncodeToString(hasher.Sum(nil))[0:10])
}
