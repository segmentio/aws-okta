package oktasamlcredentialsprovider

import "github.com/aws/aws-sdk-go/service/sts"

// TODO
type sessionCacheKey struct {
	TargetRoleARN string
}

type sessionCacheValue struct {
	sts.Credentials
}

// TODO: this needs expiry?
type sessionCache interface {
	Get(sessionCacheKey) (sessionCacheValue, error)
	Put(sessionCacheKey, sessionCacheValue) error
}

// TODO: AdaptSessionCacheFromSecureKV
