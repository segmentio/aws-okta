package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/segmentio/aws-okta/lib/client/types"
	log "github.com/sirupsen/logrus"
)

const (
	// OktaServerUs is the united states region okta domain
	OktaServerUs = "okta.com"

	// OktaserverEmea is the europe, middle east and africa region okta domain
	OktaServerEmea = "okta-emea.com"

	// OktaserverPreview is the preview domain for testing future okta releases
	OktaServerPreview = "oktapreview.com"
)

// GetOKtaDomain looks up the okta domain based on the region. For example, the okta domain
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

func parseOktaError(res *http.Response) (*types.OktaErrorResponse, error) {
	var errResp = types.OktaErrorResponse{}
	err := json.NewDecoder(res.Body).Decode(&errResp)
	if err != nil {
		log.Debug("parseOktaError parsing error: ", err)
		// we failed to parse the error. return that parse error
		return nil, err
	}
	log.Debug("Error from Okta: ", errResp)
	return &errResp, nil
}
