package assumerolewithsaml

// TODO
type sessionCacheKey struct {
	TargetRoleARN string
}

type SessionCache interface {
	Get(sessionCacheKey) (Creds, error)
	Put(sessionCacheKey, Creds) error
}

// TODO: AdaptSessionCacheFromSecureKV
