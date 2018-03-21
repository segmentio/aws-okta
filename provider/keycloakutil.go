package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
)

const (
	keycloakCookie = "KEYCLOAK_IDENTITY"
)

type KeycloakProvider struct {
	Keyring         keyring.Keyring
	ProfileName     string
	ApiBase         string
	AwsSAMLPath     string
	AwsOIDCPath     string
	AwsClient       string
	AwsClientSecret string
	kcToken         string
	kcCreds         KeycloakCreds
}

type KeycloakCreds struct {
	Username string
	Password string
}

type KeycloakUserAuthn struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshTokenExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken          string `json:"refresh_token"`
	TokenType             string `json:"token_type"`
	SessionState          string `json:"session_state"`
}

func NewKeycloakProvider(kr keyring.Keyring, profile string, kcConf map[string]string) (*KeycloakProvider, error) {
	p := KeycloakProvider{
		Keyring:     kr,
		ProfileName: profile,
	}
	if v, e := kcConf["keycloak_base"]; e {
		p.ApiBase = v
	} else {
		return nil, errors.New("Config must specify keycloak_base")
	}
	if v, e := kcConf["aws_saml_path"]; e {
		p.AwsSAMLPath = v
	} else {
		return nil, errors.New("Config must specify aws_saml_path")
	}
	if v, e := kcConf["aws_oidc_path"]; e {
		p.AwsOIDCPath = v
	} else {
		return nil, errors.New("Config must specify aws_oidc_path")
	}
	if v, e := kcConf["aws_client_id"]; e {
		p.AwsClient = v
	} else {
		return nil, errors.New("Config must specify aws_client_id")
	}
	if v, e := kcConf["aws_cliend_secret"]; e {
		p.AwsClientSecret = v
	} else {
		return nil, errors.New("Config must specify aws_cliend_secret")
	}
	return &p, nil
}

// return bool is whether the creds should be stored in keyring if they work
func (p *KeycloakProvider) retrieveKeycloakCreds() bool {
	var keycloakCreds KeycloakCreds
	keyName := p.keycloakkeyname()

	item, err := p.Keyring.Get(keyName)
	if err == nil {
		log.Debug("found creds in keyring")
		if err = json.Unmarshal(item.Data, &keycloakCreds); err != nil {
			log.Error("could not unmarshal keycloak creds")
		} else {
			p.kcCreds = keycloakCreds
			return false
		}
	} else {
		log.Debugf("couldnt get keycloak creds from keyring: %s", keyName)
		p.kcCreds = p.promptUsernamePassword()
	}
	return true
}

func (p *KeycloakProvider) storeKeycloakCreds() {
	encoded, err := json.Marshal(p.kcCreds)
	// failure would be surprising, but jsut dont save
	if err != nil {
		log.Debugf("Couldn't marshal keycloak creds... %s", err)
	} else {
		keyName := p.keycloakkeyname()
		newKeycloakItem := keyring.Item{
			Key:   keyName,
			Data:  encoded,
			Label: keyName + " credentials",
			KeychainNotTrustApplication: false,
		}
		if err := p.Keyring.Set(newKeycloakItem); err != nil {
			log.Debugf("Failed to write keycloak creds to keyring!")
		} else {
			log.Debugf("Successfully stored keycloak creds to keyring!")
		}
	}
}

func (p *KeycloakProvider) promptUsernamePassword() (creds KeycloakCreds) {
	fmt.Printf("Enter username/password for keycloak (env: %s)\n", p.ProfileName)
	for creds.Username == "" {
		u, err := Prompt("Username", false)
		if err != nil {
			fmt.Printf("Invalid username: %s\n", creds.Username)
		} else {
			creds.Username = u
		}
	}
	for creds.Password == "" {
		x, err := Prompt("Password", true)
		if err != nil {
			fmt.Printf("Invalid password: %s\n", creds.Username)
		} else {
			creds.Password = x
		}
	}
	fmt.Println("")
	return
}

func (p *KeycloakProvider) keycloakkeyname() string {
	return "keycloak-creds-" + p.ProfileName
}

func (p *KeycloakProvider) basicAuth() error {
	payload := url.Values{}
	payload.Set("username", p.kcCreds.Username)
	payload.Set("password", p.kcCreds.Password)
	payload.Set("client_id", p.AwsClient)
	payload.Set("client_secret", p.AwsClientSecret)
	payload.Set("grant_type", "password")

	header := http.Header{
		"Accept":       []string{"application/json"},
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	}

	body, err := p.doHttp("POST", p.AwsOIDCPath, header, []byte(payload.Encode()))
	if err != nil {
		return nil
	}

	var userAuthn KeycloakUserAuthn
	err = json.Unmarshal(body, &userAuthn)
	if err != nil {
		return err
	}
	log.Debug("successfully authenticated to keycloak")
	p.kcToken = userAuthn.AccessToken
	return nil
}

func (p *KeycloakProvider) getSamlAssertion() (assertion SAMLAssertion, err error) {
	header := http.Header{
		"Cookie": []string{fmt.Sprintf("%s=%s", keycloakCookie, p.kcToken)},
	}
	body, err := p.doHttp("GET", p.AwsSAMLPath, header, nil)
	if err != nil {
		return
	}

	if err = ParseSAML(body, &assertion); err != nil {
		err = fmt.Errorf("Couldn't access SAML app; is the user %s in a group that has access to AWS? (%s)", p.kcCreds.Username, err)
	}
	return
}

func (p *KeycloakProvider) doHttp(method, path string, header http.Header, data []byte) (body []byte, err error) {
	url, err := url.Parse(fmt.Sprintf("%s/%s", p.ApiBase, path))
	if err != nil {
		return
	}

	req := &http.Request{
		Method: method,
		URL:    url,
		Header: header,
		Body:   ioutil.NopCloser(bytes.NewReader(data)),
	}

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", method, url, res.Status)
		return
	}

	body, err = ioutil.ReadAll(res.Body)
	return
}
