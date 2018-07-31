package o2cli

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/Sirupsen/logrus"
	rndm "github.com/nmrshll/rndm-go"
	"github.com/skratchdot/open-golang/open"
)

func Authorize(conf *oauth2.Config) (*oauth2.Token, error) {
	o := Oauth2CLI{
		Conf: conf,
	}
	return o.Authorize()
}

type Oauth2CLI struct {
	Log  *logrus.Logger
	Conf *oauth2.Config
}

func (o *Oauth2CLI) init() {
	if o.Log == nil {
		o.Log = logrus.StandardLogger()
	}
}

func (o *Oauth2CLI) Authorize() (*oauth2.Token, error) {
	o.init()

	errorC := make(chan error, 1)
	successC := make(chan *oauth2.Token, 1)
	state := rndm.String(8)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := o.handle(r, state)
		if err != nil {
			errorC <- err
			fmt.Fprintf(w, renderError(err))
			return
		}
		successC <- token
		fmt.Fprintf(w, renderSuccess())
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	o.Conf.RedirectURL = fmt.Sprintf("%s%s", server.URL, "/callback")
	url := o.Conf.AuthCodeURL(state)

	o.Log.Infof("If browser window does not open automatically, open it by clicking on the link:\n %s", url)
	open.Run(url)
	o.Log.Infof("Waiting for response on: %s", server.URL)

	select {
	case err := <-errorC:
		o.Log.Errorf("Error in callback: %v", err)
		return nil, err
	case token := <-successC:
		o.Log.Info("Successfully exchanged for Access Token")
		return token, nil
	case <-time.After(60 * time.Second):
		o.Log.Error("Timed out waiting for callback")
		return nil, errors.New("Timed out waiting for callback")
	}
}

func (o *Oauth2CLI) handle(r *http.Request, expectedState string) (*oauth2.Token, error) {
	if r.URL.Path != "/callback" {
		return nil, errors.New("callback has incorrect path. should be `/callback`")
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		return nil, errors.New("callback missing required query param `state`")
	}
	if state != expectedState {
		return nil, errors.New("callback state invalid")
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("callback missing required query param `code`")
	}
	oauth2.RegisterBrokenAuthHeaderProvider(o.Conf.Endpoint.TokenURL)
	return o.Conf.Exchange(context.Background(), code)
}

func renderSuccess() string {
	return `
	<div style="height:100px; width:100%!; display:flex; flex-direction: column; justify-content: center; align-items:center; background-color:#2ecc71; color:white; font-size:22"><div>Success!</div></div>
		<p style="margin-top:20px; font-size:18; text-align:center">You are authenticated, you can now return to the program. This will auto-close</p>
		<script>window.onload=function(){setTimeout(this.close, 4000)}</script>
	`
}

func renderError(e error) string {
	return `
	<div style="height:100px; width:100%!; display:flex; flex-direction: column; justify-content: center; align-items:center; background-color:#ee2c21; color:white; font-size:22"><div>Failure</div></div>
	<p style="margin-top:20px; font-size:18; text-align:center">Authentication failed after receiving callback. Error: ` + e.Error() + `</p>
	`
}
