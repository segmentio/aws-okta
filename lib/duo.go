package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	u2f "github.com/Pryz/go-u2fhost"
)

type DuoClient struct {
	Host       string
	Signature  string
	Callback   string
	StateToken string
	Type       string
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
	var sid, tx, txid string
	var status StatusResp

	tx = strings.Split(d.Signature, ":")[0]

	sid, err = d.DoAuth(tx)
	if err != nil {
		return
	}

	txid, err = d.DoPrompt(sid)
	if err != nil {
		return
	}

	status, err = d.DoStatus(txid, sid)
	if err != nil {
		return
	}

	fmt.Println(status)

	if len(status.Response.U2FSignRequest) < 1 {
		err = fmt.Errorf("No u2f sign request")
		return
	}

	//TODO: from the FIDO U2F specification the Facet should from the same domain
	// as the AppID.
	u2fReq := &u2f.AuthenticateRequest{
		Challenge:       status.Response.U2FSignRequest[0].Challenge,
		AppId:           status.Response.U2FSignRequest[0].AppID,
		Facet:           status.Response.U2FSignRequest[0].AppID,
		KeyHandle:       status.Response.U2FSignRequest[0].KeyHandle,
		ChannelIdUnused: true,
	}
	u2fResp, _ := json.Marshal(authenticateHelper(u2fReq, u2f.Devices()))
	txid, err = d.DoU2fPrompt(sid, u2fResp)
	if err != nil {
		return
	}

	// This one should block until 2fa completed
	status, err = d.DoStatus(txid, sid)
	if err != nil {
		return
	}

	err = d.DoCallback(status.Response.Cookie)
	if err != nil {
		return
	}

	return
}

// DoAuth sends a POST request to the Duo /frame/web/v1/auth endpoint.
// The request will not follow the redirect and retrieve the location from the HTTP header.
// From the Location we get the Duo Session ID (sid) required for the rest of the communication.
//
// The function will return the sid
func (d *DuoClient) DoAuth(tx string) (sid string, err error) {
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

	req, err = http.NewRequest("POST", url, nil)
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
	} else {
		err = fmt.Errorf("Request failed or followed redirect: %d", res.StatusCode)
	}

	return
}

const (
	duoPromptPush = "device=phone1&facter=Duo+Push&out_of_date=False"
	duoPromptU2f  = "device=u2f_token&factor=U2F+Token"
)

// DoPrompt sends a POST request to the Duo /frame/promt endpoint
//
// The functions returns the Duo transaction ID which is different from
// the Okta transaction ID
func (d *DuoClient) DoPrompt(sid string) (txid string, err error) {
	var req *http.Request

	url := "https://" + d.Host + "/frame/prompt"

	client := &http.Client{}

	promptData := "sid=" + sid + "&" + duoPromptU2f

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

func (d *DuoClient) DoU2fPrompt(sid string, data []byte) (txid string, err error) {
	var req *http.Request

	pUrl := "https://" + d.Host + "/frame/prompt"

	client := &http.Client{}

	promptData := "sid=" + sid + "&device=u2f_token&factor=u2f_finish&out_of_date=False&days_out_of_date=0&days_to_block=None&"
	//promptData := "sid=" + sid + "&device=u2f_token&factor=u2f_finish&"
	finalData := []byte(promptData)

	fmt.Printf("\n%s\n", string(data))

	vdata, err := url.ParseQuery("response_data=" + string(data))
	if err != nil {
		return "", err
	}
	finalData = append(finalData, []byte(vdata.Encode())...)
	//finalData = append(finalData, data...)

	req, err = http.NewRequest("POST", pUrl, bytes.NewReader(finalData))
	if err != nil {
		return
	}

	requestDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	req.Header.Add("Origin", "https://"+d.Host)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("U2f prompt request failed: %d", res.StatusCode)
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
func (d *DuoClient) DoStatus(txid, sid string) (status StatusResp, err error) {
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
		err = fmt.Errorf("Status request failed: %d", res.StatusCode)
		return
	}

	err = json.NewDecoder(res.Body).Decode(&status)

	if status.Response.Result != "SUCCESS" || status.Response.Result != "OK" {
		fmt.Printf("%v\n", status)
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

	fmt.Println(auth)

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
		err = fmt.Errorf("Callback request failed: %d %s", res.StatusCode)
		return
	}
	return
}
