// types and constants for (un)marshalling Okta API
package marshal

type UserAuthn struct {
	StateToken   string            `json:"stateToken"`
	SessionToken string            `json:"sessionToken"`
	ExpiresAt    string            `json:"expiresAt"`
	Status       string            `json:"status"`
	Embedded     UserAuthnEmbedded `json:"_embedded"`
	FactorResult string            `json:"factorResult"`
}

type StateToken struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode"`
}

type UserAuthnEmbedded struct {
	Factors []UserAuthnFactor `json:"factors"`
	Factor  UserAuthnFactor   `json:"factor"`
}
type UserAuthnFactor struct {
	Id         string                  `json:"id"`
	FactorType string                  `json:"factorType"`
	Provider   string                  `json:"provider"`
	Embedded   UserAuthnFactorEmbedded `json:"_embedded"`
	Profile    UserAuthnFactorProfile  `json:"profile"`
}
type UserAuthnFactorProfile struct {
	CredentialId string `json:"credentialId"`
	AppId        string `json:"appId"`
	Version      string `json:"version"`
}

type UserAuthnFactorEmbedded struct {
	Verification UserAuthnFactorEmbeddedVerification `json:"verification"`
	Challenge    UserAuthnFactorEmbeddedChallenge    `json:"challenge"`
}
type UserAuthnFactorEmbeddedVerification struct {
	Host         string                                   `json:"host"`
	Signature    string                                   `json:"signature"`
	FactorResult string                                   `json:"factorResult"`
	Links        UserAuthnFactorEmbeddedVerificationLinks `json:"_links"`
}

type UserAuthnFactorEmbeddedChallenge struct {
	Nonce           string `json:"nonce"`
	TimeoutSeconnds int    `json:"timeoutSeconds"`
}
type UserAuthnFactorEmbeddedVerificationLinks struct {
	Complete UserAuthnFactorEmbeddedVerificationLinksComplete `json:"complete"`
}

type UserAuthnFactorEmbeddedVerificationLinksComplete struct {
	Href string `json:"href"`
}

type ErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorSummary string `json:"errorSummary"`
	ErrorId      string `json:"errorId"`
	ErrorCauses  []ErrorCause
}

type ErrorCause struct {
	ErrorSummary string `json:"errorSummary"`
}

const (
	UserAuthnStatusMFARequired     = "MFA_REQUIRED"
	UserAuthnStatusPasswordExpired = "PASSWORD_EXPIRED"
	UserAuthnStatusMFAChallenge    = "MFA_CHALLENGE"
)
