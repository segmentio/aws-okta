// TODO refactor?
package duoclient

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"net/url"

	u2fhost "github.com/marshallbrekka/go-u2fhost"

	uniformResourceLocator "net/url"

	"golang.org/x/net/html"
)

type DuoClient struct {
	Host       string
	Signature  string
	Callback   string
	Device     string
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
		ResultURL  string `json:"result_url"`
	} `json:"response"`
	Stat string `json:"stat"`
}

type PromptResp struct {
	Response struct {
		Txid string `json:"txid"`
	} `json:"response"`
	Stat string `json:"stat"`
}

func New(host, signature, callback string) *DuoClient {
	return &DuoClient{
		Host:      host,
		Signature: signature,
		Device:    "phone1",
		Callback:  callback,
	}
}

type FacetResponse struct {
	TrustedFacets []struct {
		Ids     []string `json:"ids"`
		Version struct {
			Major int `json:"major"`
			Minor int `json:"minor"`
		} `json:"version"`
	} `json:"trustedFacets"`
}

// U2F Signing Request returns some trusted urls that we need to lookup
func (d *DuoClient) getTrustedFacet(appId string) (facetResponse *FacetResponse, err error) {

	client := &http.Client{}

	req, err := http.NewRequest("GET", appId, nil)
	if err != nil {
		return
	}

	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	facetResponse = &FacetResponse{}
	err = json.NewDecoder(res.Body).Decode(facetResponse)
	if err != nil {
		return
	}

	return
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
func (d *DuoClient) ChallengeU2f(verificationHost string) (err error) {
	var sid, tx, txid, auth string
	var status = StatusResp{}

	tx = strings.Split(d.Signature, ":")[0]

	sid, err = d.DoAuth(tx, "", "")
	if err != nil {
		return
	}

	txid, err = d.DoPrompt(sid)
	if err != nil {
		return
	}

	auth, status, err = d.DoStatus(txid, sid)
	if err != nil {
		return
	}

	if status.Response.StatusCode == "u2f_sent" {
		var response *u2fhost.AuthenticateResponse
		allDevices := u2fhost.Devices()
		// Filter only the devices that can be opened.
		openDevices := []u2fhost.Device{}
		for i, device := range allDevices {
			err := device.Open()
			if err == nil {
				openDevices = append(openDevices, allDevices[i])
				defer func(i int) {
					allDevices[i].Close()
				}(i)
			}
		}
		if len(openDevices) == 0 {
			return errors.New("no open u2f devices")
		}

		var (
			err error
		)
		prompted := false
		timeout := time.After(time.Second * 25)
		interval := time.NewTicker(time.Millisecond * 250)
		facet := "https://" + verificationHost
		log.Debugf("Facet: %s", facet)
		var req = &u2fhost.AuthenticateRequest{
			Challenge: status.Response.U2FSignRequest[0].Challenge,
			AppId:     status.Response.U2FSignRequest[0].AppID,
			KeyHandle: status.Response.U2FSignRequest[0].KeyHandle,
			Facet:     facet,
		}
		defer interval.Stop()
		for {
			if response != nil {
				break
			}
			select {
			case <-timeout:
				fmt.Println("Failed to get registration response after 25 seconds")
				break
			case <-interval.C:
				for _, device := range openDevices {
					response, err = device.Authenticate(req)
					if err == nil {
						log.Printf("Authentication succeeded, continuing")
					} else if _, ok := err.(*u2fhost.TestOfUserPresenceRequiredError); ok {
						if !prompted {
							fmt.Println("Touch the flashing U2F device to authenticate...")
							fmt.Println()
						}
						prompted = true
					} else {
						fmt.Printf("Got status response %#v\n", err)
						break
					}
				}
			}
		}
		//log.Debugf("response: %#v", response)
		//if response != nil {
		txid, err = d.DoU2FPromptFinish(sid, status.Response.U2FSignRequest[0].SessionID, response)
		if err != nil {
			return fmt.Errorf("Failed on U2F_final. Err: %s", err)
		}
		//}
	}

	log.Printf("Device: %s", d.Device)

	// So, turns out that if you call DoStatus in
	// Duo's token mode, it will return an auth token
	// immediately if successful, because it's a single check
	// but for Push you get empty value and have to
	// wait on second response post-push
	if d.Device != "token" {
		// This one should block untile 2fa completed
		auth, _, err = d.DoStatus(txid, sid)
		if err != nil {
			return
		}
	}

	err = d.DoCallback(auth)
	if err != nil {
		return
	}
	return
}

// It's same as u2fhost.AuthenticateResponse but needs SessionID for Duo/Okta
type ResponseData struct {
	ClientData    string `json:"clientData"`
	KeyHandle     string `json:"keyHandle"`
	SessionID     string `json:"sessionId"`
	SignatureData string `json:"signatureData"`
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
		sid, _ = getNode(doc, "sid")
		certsURL, _ := getNode(doc, "certs_url")
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
func (d *DuoClient) DoU2FPromptFinish(sid string, sessionID string, resp *u2fhost.AuthenticateResponse) (txid string, err error) {
	var (
		req        *http.Request
		promptData string
	)

	promptUrl := "https://" + d.Host + "/frame/prompt"

	client := &http.Client{}

	var respData = ResponseData{
		SessionID:     sessionID,
		KeyHandle:     resp.KeyHandle,
		ClientData:    resp.ClientData,
		SignatureData: resp.SignatureData,
	}

	respJSON, err := json.Marshal(respData)
	if err != nil {
		return
	}

	// Pick between device you want to use -- the flow are bit different depending on
	// whether you want to use a token or a phone of some sort
	// it may make sense to make a selector in CLI similar to the Okta UI but
	// I'm not certain that belongs here
	if d.Device == "u2f" {
		promptData = "sid=" + sid + "&device=u2f_token&factor=u2f_finish&out_of_date=False&days_out_of_date=0&response_data=" + url.QueryEscape(string(respJSON))
	} else {
		err = fmt.Errorf("U2F Prompt final only applies to u2f devices, not %s", d.Device)
		return
	}

	req, err = http.NewRequest("POST", promptUrl, bytes.NewReader([]byte(promptData)))
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
		err = fmt.Errorf("U2F Prompt request failed: %d", res.StatusCode)
		return
	}

	var status PromptResp
	err = json.NewDecoder(res.Body).Decode(&status)

	txid = status.Response.Txid

	return
}

// DoPrompt sends a POST request to the Duo /frame/promt endpoint
//
// The functions returns the Duo transaction ID which is different from
// the Okta transaction ID
func (d *DuoClient) DoPrompt(sid string) (txid string, err error) {
	var (
		req        *http.Request
		promptData string
	)

	url := "https://" + d.Host + "/frame/prompt"

	client := &http.Client{}

	// Pick between device you want to use -- the flow are bit different depending on
	// whether you want to use a token or a phone of some sort
	// it may make sense to make a selector in CLI similar to the Okta UI but
	// I'm not certain that belongs here
	if d.Device == "token" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Press button on your hardware token: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("Failed to read the stdin for hardware token auth: %s", err)
		}
		text = strings.TrimSpace(text)
		//fmt.Println(text)

		promptData = "sid=" + sid + "&device=token&factor=Passcode&passcode=" + text + "&out_of_date=False&days_out_of_date=0"
	} else if d.Device == "u2f" {
		promptData = "sid=" + sid + "&device=u2f_token&factor=U2F+Token&out_of_date=False&days_out_of_date=0"
	} else {
		promptData = "sid=" + sid + "&device=" + d.Device + "&factor=Duo+Push&out_of_date=False"
	}

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
func (d *DuoClient) DoStatus(txid, sid string) (auth string, status StatusResp, err error) {
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

	err = json.NewDecoder(res.Body).Decode(&status)

	if status.Response.Result == "SUCCESS" {
		if status.Response.ResultURL != "" {
			auth, err = d.DoRedirect(status.Response.ResultURL, sid)
		} else {
			auth = status.Response.Cookie
		}
	}
	return
}

func (d *DuoClient) DoRedirect(url string, sid string) (string, error) {
	client := http.Client{}
	statusData := "sid=" + sid
	url = "https://" + d.Host + url
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(statusData)))
	if err != nil {
		return "", err
	}

	req.Header.Add("Origin", "https://"+d.Host)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("X-Requested-With", "XMLHttpRequest")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("DUO: bad status from result_url: %d", res.StatusCode)
		return "", err
	}

	var status StatusResp
	err = json.NewDecoder(res.Body).Decode(&status)
	if err != nil {
		return "", err
	}
	return status.Response.Cookie, nil
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

// TODO: document this mysterious monstrosity
func getNode(n *html.Node, name string) (val string, node *html.Node) {
	var isMatch bool
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, a := range n.Attr {
			if a.Key == "name" && a.Val == name {
				isMatch = true
			}
			if a.Key == "value" && isMatch {
				val = a.Val
			}
		}
	}
	if node == nil || val == "" {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			val, node = getNode(c, name)
			if val != "" {
				return
			}
		}
	}
	return
}
