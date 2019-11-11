package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

const (
	OktaServerUs      = "okta.com"
	OktaServerEmea    = "okta-emea.com"
	OktaServerPreview = "oktapreview.com"
)

// looks up the okta domain based on the region. For example, the okta domain
// for "us" is `okta.com` making your api domain as `<your-org>.okta.com`
func GetOktaDomain(region string) (string, error) {
	switch region {
	case "us":
		return OktaServerUs, nil
	case "emea":
		return OktaServerEmea, nil
	case "preview":
		return OktaServerPreview, nil
	}
	return "", fmt.Errorf("invalid region %s", region)
}

// validate the MFA factor is supported
func isFactorSupported(factor MFAConfig) error {
	var validationErrorMessage string
	switch factor.FactorType {
	case "web":
	case "token:software:totp":
	case "token:hardware":
	case "sms":
	case "u2f":
	case "token":
		if factor.Provider != "SYMANTEC" {
			validationErrorMessage = fmt.Sprintf("provider %s with factor token not supported.", factor.Provider)
		}
	case "push":
		if factor.Provider != "OKTA" && factor.Provider != "DUO" {
			validationErrorMessage = fmt.Sprintf("provider %s with factor token not supported.", factor.Provider)
		}
	default:
		validationErrorMessage = fmt.Sprintf("provider %s with factor token not supported.", factor.Provider)
	}
	if validationErrorMessage != "" {
		return fmt.Errorf("%v %w", validationErrorMessage, ErrNotImplemented)
	}
	return nil
}

func parseOktaError(res *http.Response) (*oktaErrorResponse, error) {
	var errResp = oktaErrorResponse{}
	err := json.NewDecoder(res.Body).Decode(&errResp)
	if err != nil {
		log.Debug("parseOktaError parsing error: ", err)
		// we failed to parse the error. return that parse error
		return nil, err
	}
	log.Debug("Error from Okta: ", errResp)
	return &errResp, nil
}
