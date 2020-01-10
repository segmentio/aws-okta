package oktasamlcredentialsprovider

import awscredentials "github.com/aws/aws-sdk-go/aws/credentials"

// TODO
type sessionCacheKey struct {
	TargetRoleARN string
}

type sessionCacheValue struct {
	awscredentials.Value
}

// TODO: this needs expiry?
type sessionCache interface {
	Get(sessionCacheKey) (sessionCacheValue, error)
	Put(sessionCacheKey, sessionCacheValue) error
}

// TODO: AdaptSessionCacheFromSecureKV
