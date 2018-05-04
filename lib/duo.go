package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	uniformResourceLocator "net/url"

	"golang.org/x/net/html"
)

type DuoClient struct {
	Host       string
	Signature  string
	Callback   string
	StateToken string
}

type StatusResp struct {
	Response struct {
		U2FSignRequest []struct {
			Version   string `json:"version"`
			Challenge string `json:"challenge"`
			AppID     string `json:"appId"`
			KeyHandle string `json:"keyHandle"`
			SessionID string `json:"sessionId"`
		} `json:"u2f_sign_request"`
		Status     string `json:"status"`
		StatusCode string `json:"status_code"`
		Reason     string `json:"reason"`
		Parent     string `json:"parent"`
		Cookie     string `json:"cookie"`
		Result     string `json:"result"`
	} `json:"response"`
	Stat string `json:"stat"`
}

type PromptResp struct {
	Response struct {
		Txid string `json:"txid"`
	} `json:"response"`
	Stat string `json:"stat"`
}

func NewDuoClient(host, signature, callback string) *DuoClient {
	return &DuoClient{
		Host:      host,
		Signature: signature,
		Callback:  callback,
	}
}

// ChallengeU2F performs multiple call against an obscure Duo API.
//
// Normally you use an iframe to perform those calls but here the main idea is
// to fake Duo is order to use the CLI without any browser.
//
// The function perform three successive calls to retry the challenge data.
// Wait for the user to perform the verification (Duo Push or Yubikey). And then
// call the callback url.
//
// TODO: Use a Context to gracefully shutdown the thing and have a nice timeout
func (d *DuoClient) ChallengeU2f() (err error) {
	var sid, tx, txid, auth string

	tx = strings.Split(d.Signature, ":")[0]

	sid, err = d.DoAuth(tx, "", "")
	if err != nil {
		return
	}

	txid, err = d.DoPrompt(sid)
	if err != nil {
		return
	}

	_, err = d.DoStatus(txid, sid)
	if err != nil {
		return
	}

	// This one should block untile 2fa completed
	auth, err = d.DoStatus(txid, sid)
	if err != nil {
		return
	}

	err = d.DoCallback(auth)
	if err != nil {
		return
	}

	return
}

// DoAuth sends a POST request to the Duo /frame/web/v1/auth endpoint.
// The request will not follow the redirect and retrieve the location from the HTTP header.
// From the Location we get the Duo Session ID (sid) required for the rest of the communication.
// In some integrations of Duo, an empty POST to the Duo /frame/web/v1/auth endpoint will return
// StatusOK with a form of hidden inputs. In that case, we redo the POST with data from the
// hidden inputs, which triggers the usual redirect/location flow and allows for a successful
// authentication.
//
// The function will return the sid
func (d *DuoClient) DoAuth(tx string, inputSid string, inputCertsURL string) (sid string, err error) {
	var req *http.Request
	var location string

	url := fmt.Sprintf(
		"https://%s/frame/web/v1/auth?tx=%s&parent=http://0.0.0.0:3000/duo&v=2.1",
		d.Host, tx,
	)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	data := uniformResourceLocator.Values{}
	if inputSid != "" && inputCertsURL != "" {
		data.Set("sid", inputSid)
		data.Set("certs_url", inputCertsURL)
	}

	req, err = http.NewRequest("POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return
	}

	req.Header.Add("Origin", "https://"+d.Host)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusFound {
		location = res.Header.Get("Location")
		if location != "" {
			sid = strings.Split(location, "=")[1]
		} else {
			err = fmt.Errorf("Location not part of the auth header. Authentication failed ?")
		}
	} else if res.StatusCode == http.StatusOK && inputCertsURL == "" && inputSid == "" {
		doc, err := html.Parse(res.Body)
		if err != nil {
			err = fmt.Errorf("Can't parse response")
		}
		sid, _ = GetNode(doc, "sid")
		certsURL, _ := GetNode(doc, "certs_url")
		sid, err = d.DoAuth(tx, sid, certsURL)
	} else {
		err = fmt.Errorf("Request failed or followed redirect: %d", res.StatusCode)
	}

	return
}

// DoPrompt sends a POST request to the Duo /frame/promt endpoint
//
// The functions returns the Duo transaction ID which is different from
// the Okta transaction ID
func (d *DuoClient) DoPrompt(sid string) (txid string, err error) {
	var req *http.Request

	url := "https://" + d.Host + "/frame/prompt"

	client := &http.Client{}

	//TODO: Here we automatically use Duo Push. The user should be able to choose
	//between Duo Push and the Yubikey ("&device=u2f_token&factor=U2F+Token")
	promptData := "sid=" + sid + "&device=phone1&factor=Duo+Push&out_of_date=False"
	req, err = http.NewRequest("POST", url, bytes.NewReader([]byte(promptData)))
	if err != nil {
		return
	}

	req.Header.Add("Origin", "https://"+d.Host)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("Prompt request failed: %d", res.StatusCode)
		return
	}

	var status PromptResp
	err = json.NewDecoder(res.Body).Decode(&status)

	txid = status.Response.Txid

	return
}

// DoStatus sends a POST request against the Duo /frame/status endpoint
//
// The function returns the auth string required for the Okta Callback if
// the request succeeded.
func (d *DuoClient) DoStatus(txid, sid string) (auth string, err error) {
	var req *http.Request

	url := "https://" + d.Host + "/frame/status"

	client := &http.Client{}

	statusData := "sid=" + sid + "&txid=" + txid
	req, err = http.NewRequest("POST", url, bytes.NewReader([]byte(statusData)))
	if err != nil {
		return
	}

	req.Header.Add("Origin", "https://"+d.Host)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("Prompt request failed: %d", res.StatusCode)
		return
	}

	var status StatusResp
	err = json.NewDecoder(res.Body).Decode(&status)

	if status.Response.Result == "SUCCESS" {
		auth = status.Response.Cookie
	}
	return
}

// DoCallback send a POST request to the Okta callback url defined in the DuoClient
//
// The callback request requires the stateToken from Okta and a sig_response built
// from the precedent requests.
func (d *DuoClient) DoCallback(auth string) (err error) {
	var app string
	var req *http.Request

	app = strings.Split(d.Signature, ":")[1]

	sigResp := auth + ":" + app

	client := &http.Client{}

	callbackData := "stateToken=" + d.StateToken + "&sig_response=" + sigResp
	req, err = http.NewRequest("POST", d.Callback, bytes.NewReader([]byte(callbackData)))
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("Prompt request failed: %d", res.StatusCode)
		return
	}
	return
}
