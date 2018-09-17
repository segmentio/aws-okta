package lib

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	log "github.com/sirupsen/logrus"
)

const (
	RedirectAddr = "127.0.0.1:5556"
	RedirectPath = "/auth/okta/callback"
)

type OktaOIDCClient struct {
	Organization  string
	Username      string
	OIDCAppID     string
	State         string
	CodeVerifier  string
	CodeChallenge string
}

func NewOktaOIDCClient(creds OktaCreds, oidcAppID string) (*OktaOIDCClient, error) {
	state, err := randomHex(20)
	if err != nil {
		return nil, err
	}
	codeVerifier, codeChallenge, err := pkce()
	if err != nil {
		return nil, err
	}

	return &OktaOIDCClient{
		OIDCAppID:     oidcAppID,
		Organization:  creds.Organization,
		Username:      creds.Username,
		State:         state,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
	}, nil
}

func (o *OktaOIDCClient) AuthenticateProfile(profileARN string, duration time.Duration) (sts.Credentials, error) {
	// Allow the whole operation to maximally take 2 minutes. Should be enough
	// to cover different network delays + fumbling to find an MFA device etc.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	// Make sure early returns close all open connections etc
	defer cancel()

	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("https://%s.%s", o.Organization, OktaServerDefault))
	if err != nil {
		return sts.Credentials{}, err
	}
	oidcConfig := &oidc.Config{
		ClientID: o.OIDCAppID,
	}
	verifier := provider.Verifier(oidcConfig)
	config := oauth2.Config{
		ClientID:    o.OIDCAppID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: fmt.Sprintf("http://%s%s", RedirectAddr, RedirectPath),
		Scopes:      []string{oidc.ScopeOpenID},
	}

	credChan := make(chan *sts.Credentials, 1)
	o.setRedirectHandler(ctx, cancel, credChan, config, verifier, profileARN, duration)

	srv := o.startRedirectServer()
	defer o.stopRedirectServer(srv)

	var newCreds sts.Credentials
	err = restoreWindowFocusAfter(func() error {
		err := browser.OpenURL(config.AuthCodeURL(o.State,
			oauth2.SetAuthURLParam("code_challenge", o.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		))
		if err != nil {
			return err
		}

		select {
		case creds := <-credChan:
			newCreds = *creds
		case <-ctx.Done():
			log.Debugf("Didn't get credentials with OIDC. Context done: %s", ctx.Err())
			return errors.New("Failed to get credentials with OIDC")
		}

		return nil
	})
	return newCreds, err
}

func (o *OktaOIDCClient) setRedirectHandler(
	ctx context.Context,
	cancel context.CancelFunc,
	credChan chan *sts.Credentials,
	config oauth2.Config,
	verifier *oidc.IDTokenVerifier,
	profileARN string,
	duration time.Duration,
) {
	http.HandleFunc(RedirectPath, func(w http.ResponseWriter, r *http.Request) {
		// Whatever the result, the authentication is done after we finish
		// handling this redirected request.
		defer cancel()
		// As this is still mainly a CLI tool, we can return this generic
		// response to the browser on any outcome.
		defer w.Write([]byte("This tab/window can safely be closed"))

		log.Debug("Received redirect request")

		if r.URL.Query().Get("state") != o.State {
			log.Error("OIDC redirect state did not match")
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"),
			oauth2.SetAuthURLParam("code_verifier", o.CodeVerifier),
		)
		if err != nil {
			log.Errorf("Failed to exchange OIDC token: %s", err.Error())
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Error("No id_token field in oauth2 token")
			return
		}
		_, err = verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Errorf("Failed to verify OIDC token: %s", err.Error())
			return
		}

		log.Debug("Verified OIDC token. Using the ID token to assume an AWS role.")
		sess := session.Must(session.NewSession())
		svc := sts.New(sess)
		params := &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(profileARN),
			RoleSessionName:  aws.String(o.Username),
			WebIdentityToken: aws.String(rawIDToken),
			DurationSeconds:  aws.Int64(int64(duration.Seconds())),
		}
		assumeResp, err := svc.AssumeRoleWithWebIdentity(params)
		if err != nil {
			log.WithField("role", profileARN).Errorf("Error assuming role with OIDC: %s", err.Error())
			return
		}
		credChan <- assumeResp.Credentials
	})
}

func (o *OktaOIDCClient) startRedirectServer() *http.Server {
	srv := &http.Server{Addr: RedirectAddr}
	go func() {
		log.Debugf("Listening for redirect on http://%s/", RedirectAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Debugf("Httpserver: ListenAndServe() error: %s", err)
		}
	}()
	return srv
}

func (o *OktaOIDCClient) stopRedirectServer(srv *http.Server) {
	log.Debug("Shutting server down")
	if err := srv.Close(); err != nil {
		// This should be safe to ignore in a CLI program, which shuts down
		// shortly after anyway
		log.Debug("Failed to shut down server. Ignoring")
	}
}

func restoreWindowFocusAfter(f func() error) error {
	if runtime.GOOS != "darwin" {
		log.Debugf("Not runninc on macOS. Will not try to restore focus to terminal.")
		f()
		return nil
	}

	windowWithFocusRaw, err := exec.Command("osascript", "-e", "tell application \"System Events\""+
		" to return name of first application process whose frontmost is true").Output()
	if eErr, ok := err.(*exec.ExitError); ok {
		log.Debugf(
			"Getting current focused window failed. Will not try restoring focus. Error: %s",
			string(eErr.Stderr),
		)
	} else if err != nil {
		return err
	}
	windowWithFocus := strings.TrimSpace(string(windowWithFocusRaw))

	// Don't return immedately, even if f returns an error. Try to restore
	// focus first.
	fErr := f()

	if err != nil {
		// Do not try to regain focus if finding the window to focus failed
		return fErr
	}

	err = exec.Command("osascript", "-e",
		fmt.Sprintf("tell application \"%s\" to activate", windowWithFocus)).Run()
	if eErr, ok := err.(*exec.ExitError); ok {
		log.Debugf("Refocusing failed. Ignoring. Error: %s", string(eErr.Stderr))
	} else if err != nil {
		return err
	}
	return fErr
}

func pkce() (string, string, error) {
	codeVerifier, err := randomHex(30)
	if err != nil {
		return "", "", err
	}

	hash := sha256.New()
	hash.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

	return codeVerifier, codeChallenge, nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
