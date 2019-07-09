package sessioncache

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
)

// duplicates lib.SessionCacheInterface
type store interface {
	Get(Key) (*Session, error)
	Put(Key, *Session) error
}

var theDistantFuture = time.Date(3000, 0, 0, 0, 0, 0, 0, time.UTC)
var theDistantPast = time.Date(1000, 0, 0, 0, 0, 0, 0, time.UTC)

type fixedKey struct {
	v string
}

func (k *fixedKey) Key() string {
	return k.v
}

func testStore(t *testing.T, storeFactory func() store) {
	tName := "put-get"
	t.Run(tName, func(t *testing.T) {
		st := storeFactory()
		sess := Session{
			Name: tName,
			Credentials: sts.Credentials{
				// avoid expiration
				Expiration: &theDistantFuture,
			},
		}
		key := fixedKey{tName}

		err := st.Put(&key, &sess)
		if err != nil {
			t.Fatalf("error on put: %s", err)
		}

		got, err := st.Get(&key)
		if err != nil {
			t.Fatalf("error on get: %s", err)
		}
		assert.Equal(t, sess, *got)
	})

	tName = "get expired should return ErrSessionExpired"
	t.Run(tName, func(t *testing.T) {
		st := storeFactory()
		sess := Session{
			Name: tName,
			Credentials: sts.Credentials{
				// avoid expiration
				Expiration: &theDistantPast,
			},
		}
		key := fixedKey{tName}

		err := st.Put(&key, &sess)
		if err != nil {
			t.Fatalf("error on put: %s", err)
		}

		_, err = st.Get(&key)
		if !xerrors.Is(err, ErrSessionExpired) {
			t.Fatalf("expected get err to be ErrSessionExpired; is %s", err)
		}
	})
}
