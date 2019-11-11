package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/manifoldco/promptui"
	"strings"

	"github.com/segmentio/aws-okta/internal/sessioncache"
	"github.com/segmentio/aws-okta/lib"
	"github.com/segmentio/aws-okta/lib/client"
	"github.com/segmentio/aws-okta/lib/provider"
	"github.com/segmentio/aws-okta/lib/session"

	"golang.org/x/xerrors"
)

type MFAInputs struct {
	Label string
}

func (s *MFAInputs) ChooseFactor(factors []client.MFAConfig) (int, error) {
	prompt := promptui.Select{
		Label: s.Label,
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}?",
			Active:   "\U0001F5DD {{ .FactorType | cyan }} ({{ .Provider | red }})",
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

type SAMLRoleChooser struct {
	Label string
}

func (c *SAMLRoleChooser) ChooseRole(roles []provider.AssumableRole) (int, error) {
	prompt := promptui.Select{
		Label: c.Label,
		Size:  20,
		Searcher: func(input string, index int) bool {
			role := roles[index]
			name := strings.Replace(strings.ToLower(role.Role), " ", "", -1)
			input = strings.Replace(strings.ToLower(input), " ", "", -1)

			return strings.Contains(name, input)
		},
		Templates: &promptui.SelectTemplates{
			Label:    "{{ . }}?",
			Active:   "\U0001F308 {{ .Role | cyan }}",
			Inactive: "  {{ .Role | cyan }}",
			Selected: "\U0001F308 {{ .Role | red | cyan }}",
		},
		Items: roles,
	}

	i, _, err := prompt.Run()

	return i, err

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
		return nil, fmt.Errorf("failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}
	oktaCreds.MFA = mfaConfig

	mfaChooser := MFAInputs{Label: "Choose the MFA to use"}

	sessionCache := session.New(*kr)
	oktaClient, err := client.NewOktaClient(oktaCreds, sessionCache, &mfaChooser, nil)
	if err != nil {
		if xerrors.Is(err, client.ErrInvalidCredentials) {
			err = xerrors.New("credentials aren't complete. To remedy this, re-add your credentials with `aws-okta add`")
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

	roleChooser := SAMLRoleChooser{Label: "Choose a role to assume"}
	p, err := provider.NewAWSSAMLProvider(sessions, profile, opts, oktaClient, &roleChooser)
	if err != nil {
		return nil, err
	}
	return p, nil
}
