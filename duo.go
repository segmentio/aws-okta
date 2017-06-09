package okta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type DuoClient struct {
	Host      string
	Signature string
	Callback  string
}

type PromptResp struct {
	Response struct {
		Txid string `json:"txid"`
	} `json:"response"`
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
// Wait for the user to perform the verification (touch the Yubikey). And then
// call the callback url.
//
// TODO: Use a Context to gracefully shutdown the thing and have a nice timeout
func (d *DuoClient) ChallengeU2f() (err error) {
	var sid string
	var tx string

	tx = strings.Split(d.Signature, ":")[0]

	// Call the auth API and retrieve the Location from the Header
	var location string
	err = d.Do("POST", "frame/web/v1/auth?tx="+tx+"&parent=http://0.0.0.0:3000/duo&v=2.1",
		[]byte("parent=http%3A%2F%2F0.0.0.0%3A3000"), nil, &location)
	if err != nil {
		return
	}
	fmt.Println(location)
	if location != "" {
		sid = strings.Split(location, "=")[1]
	} else {
		return fmt.Errorf("Location not part of the auth header. Authentication failed ?")
	}
	fmt.Printf("Location: %s\nsid: %s\n", location, sid)

	//promptHeader := http.Header{
	//	"Accept":           []string{"text/plain", "*/*"},
	//	"X-Requested-With": []string{"XMLHttpRequest"},
	//}
	//promptPayload := []byte(fmt.Sprintf("sid=%s&device=u2f_token&factor=U2F+Token", sid))
	//promptResp := PromptResp{}
	//err = d.Do("POST", "frame/prompt", promptPayload, &promptHeader, &promptResp, nil)
	//if err != nil {
	//	return
	//}

	//txid := promptResp.Response.Txid
	//fmt.Println(txid)

	return
}

func (d *DuoClient) Do(method string, path string, data []byte, recv interface{}, headerRecv interface{}) (err error) {
	var url *url.URL
	var res *http.Response

	url, err = url.Parse(fmt.Sprintf(
		"https://%s/%s", d.Host, path,
	))
	if err != nil {
		return
	}

	header := &http.Header{
		"Origin":       []string{"https://" + d.Host},
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	}

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req := &http.Request{
		Method:     method,
		URL:        url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     *header,
	}

	if res, err = client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusFound {
		err = fmt.Errorf("%s %v: %s", method, url, res.Status)
		fmt.Println(err)
	} else {
		if recv != nil {
			err = json.NewDecoder(res.Body).Decode(recv)
		}
		if headerRecv != nil {
			headerRecv = res.Header.Get("Location")
			fmt.Println(headerRecv)
		}
	}

	return
}

// mergeHeader is a helper to merge two http.Header
func mergeHeader(src, target *http.Header) {
	for k, v := range *src {
		for i := 0; i < len(v); i++ {
			target.Add(k, v[i])
		}
	}
}

func parsePromptResp(payload []byte) (txid string, err error) {
	type Prompt struct {
		Response struct {
			Txid string `json:"txid"`
		} `json:"response"`
	}
	prompt := Prompt{}
	err = json.Unmarshal(payload, &prompt)
	if err != nil {
		return
	}

	txid = prompt.Response.Txid

	return
}
