package lib

// http://developer.okta.com/docs/api/resources/authn.html
type OktaUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type OktaStateToken struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode"`
}

type OktaUserAuthn struct {
	StateToken   string                `json:"stateToken"`
	SessionToken string                `json:"sessionToken"`
	ExpiresAt    string                `json:"expiresAt"`
	Status       string                `json:"status"`
	Embedded     OktaUserAuthnEmbedded `json:"_embedded"`
	FactorResult string                `json:"factorResult"`
}

type OktaUserAuthnEmbedded struct {
	Factors []OktaUserAuthnFactor `json:"factors"`
	Factor  OktaUserAuthnFactor   `json:"factor"`
}

type OktaUserAuthnFactor struct {
	Id         string                      `json:"id"`
	FactorType string                      `json:"factorType"`
	Provider   string                      `json:"provider"`
	Embedded   OktaUserAuthnFactorEmbedded `json:"_embedded"`
	Profile    OktaUserAuthnFactorProfile  `json:"profile"`
}

type OktaUserAuthnFactorProfile struct {
	CredentialId string `json:"credentialId"`
	AppId        string `json:"appId"`
	Version      string `json:"version"`
}

type OktaUserAuthnFactorEmbedded struct {
	Verification OktaUserAuthnFactorEmbeddedVerification `json:"verification"`
	Challenge    OktaUserAuthnFactorEmbeddedChallenge    `json:"challenge"`
}

type OktaUserAuthnFactorEmbeddedVerification struct {
	Host         string                                       `json:"host"`
	Signature    string                                       `json:"signature"`
	FactorResult string                                       `json:"factorResult"`
	Links        OktaUserAuthnFactorEmbeddedVerificationLinks `json:"_links"`
}

type OktaUserAuthnFactorEmbeddedChallenge struct {
	Nonce           string `json:"nonce"`
	TimeoutSeconnds int    `json:"timeoutSeconds"`
}
type OktaUserAuthnFactorEmbeddedVerificationLinks struct {
	Complete OktaUserAuthnFactorEmbeddedVerificationLinksComplete `json:"complete"`
}

type OktaUserAuthnFactorEmbeddedVerificationLinksComplete struct {
	Href string `json:"href"`
}
