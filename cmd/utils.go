package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/manifoldco/promptui"

	"github.com/segmentio/aws-okta/internal/sessioncache"
	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/client"
	"github.com/segmentio/aws-okta/lib/provider"
	"github.com/segmentio/aws-okta/lib/session"
)

type MFAInputs struct {
	Label string
}

func (s *MFAInputs) ChooseFactor(factors []client.MFAConfig) (int, error) {
	prompt := promptui.Select{
		Label: s.Label,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}?",
			Active:   "\U0001F336 {{ .FactorType | cyan }} ({{ .Provider | red }})",
			Inactive: "  {{ .FactorType | cyan }} ({{ .Provider | red }})",
			Selected: "\U0001F336 {{ .FactorType | red | cyan }}",
			Details: `
--------- MFA ----------
{{ "Type:" | faint }}	{{ .FactorType }}
{{ "Provider:" | faint }}	{{ .Provider }}
{{ "ID:" | faint }}	{{ .Id }}`,
		},
		Items: factors,
	}

	i, _, err := prompt.Run()

	return i, err
}

func (s *MFAInputs) CodeSupplier(factor client.MFAConfig) (string, error) {
	prompt := promptui.Prompt{
		Label: "Enter your MFA code: ",
	}

	result, err := prompt.Run()
	return result, err
}

func getKeyring(backend string) (*keyring.Keyring, error) {
	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return nil, err
	}
	return &kr, nil
}

func createOktaClient(kr *keyring.Keyring, mfaConfig client.MFAConfig) (*client.OktaClient, error) {
	var oktaCreds client.OktaCredential

	item, err := (*kr).Get("okta-creds")
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return nil, fmt.Errorf("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}
	oktaCreds.MFA = mfaConfig

	mfaChooser := MFAInputs{Label: "Choose the MFA to use"}

	sessionCache := session.New(*kr)
	oktaClient, err := client.NewOktaClient(oktaCreds, sessionCache, &mfaChooser, nil)
	if err != nil {
		if errors.Is(err, client.InvalidCredentialsError) {
			err = errors.New("credentials aren't complete. To remedy this, re-add your credentials with `aws-okta add`")
		}
		return nil, err
	}
	return oktaClient, nil
}

func createAWSSAMLProvider(backend string,
	mfaConfig client.MFAConfig,
	profile string,
	opts provider.AWSSAMLProviderOptions) (*provider.AWSSAMLProvider, error) {
	var kr *keyring.Keyring
	var oktaClient *client.OktaClient
	var err error

	kr, err = getKeyring(backend)
	if err != nil {
		return nil, err
	}

	oktaClient, err = createOktaClient(kr, mfaConfig)
	if err != nil {
		return nil, err
	}
	sessions := &sessioncache.SingleKrItemStore{*kr}
	p, err := provider.NewAWSSAMLProvider(sessions, profile, opts, oktaClient)
	if err != nil {
		return nil, err
	}
	return p, nil
}
