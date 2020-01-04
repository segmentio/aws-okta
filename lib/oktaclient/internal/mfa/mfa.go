package mfa

// Input is provided to get input from the user.
type Input interface {
	CodeSupplier(factorType string) (string, error)
}

// Payload is a common request body that is sent as part of mfa validation
type Payload struct {
	StateToken string `json:"stateToken"`
	PassCode   string `json:"passCode,omitempty"`
}

const (
	ActionVerify = "verify"
)
