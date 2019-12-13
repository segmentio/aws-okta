package client

type oktaUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type oktaUserAuthn struct {
	StateToken   string                `json:"stateToken"`
	SessionToken string                `json:"sessionToken"`
	ExpiresAt    string                `json:"expiresAt"`
	Status       string                `json:"status"`
	Embedded     oktaUserAuthnEmbedded `json:"_embedded"`
	FactorResult string                `json:"factorResult"`
}
type oktaStateToken struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode"`
}

type oktaUserAuthnEmbedded struct {
	Factors []oktaUserAuthnFactor `json:"factors"`
	Factor  oktaUserAuthnFactor   `json:"factor"`
}
type oktaUserAuthnFactor struct {
	Id         string                      `json:"id"`
	FactorType string                      `json:"factorType"`
	Provider   string                      `json:"provider"`
	Embedded   oktaUserAuthnFactorEmbedded `json:"_embedded"`
	Profile    oktaUserAuthnFactorProfile  `json:"profile"`
}
type oktaUserAuthnFactorProfile struct {
	CredentialId string `json:"credentialId"`
	AppId        string `json:"appId"`
	Version      string `json:"version"`
}

type oktaUserAuthnFactorEmbedded struct {
	Verification oktaUserAuthnFactorEmbeddedVerification `json:"verification"`
	Challenge    oktaUserAuthnFactorEmbeddedChallenge    `json:"challenge"`
}
type oktaUserAuthnFactorEmbeddedVerification struct {
	Host         string                                       `json:"host"`
	Signature    string                                       `json:"signature"`
	FactorResult string                                       `json:"factorResult"`
	Links        oktaUserAuthnFactorEmbeddedVerificationLinks `json:"_links"`
}

type oktaUserAuthnFactorEmbeddedChallenge struct {
	Nonce           string `json:"nonce"`
	TimeoutSeconnds int    `json:"timeoutSeconds"`
}
type oktaUserAuthnFactorEmbeddedVerificationLinks struct {
	Complete oktaUserAuthnFactorEmbeddedVerificationLinksComplete `json:"complete"`
}

type oktaUserAuthnFactorEmbeddedVerificationLinksComplete struct {
	Href string `json:"href"`
}

type oktaErrorResponse struct {
	ErrorCode    string `json:"errorCode"`
	ErrorSummary string `json:"errorSummary"`
	ErrorId      string `json:"errorId"`
	ErrorCauses  []oktaErrorCause
}

type oktaErrorCause struct {
	ErrorSummary string `json:"errorSummary"`
}
