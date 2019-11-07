package cmd

import (
	"github.com/manifoldco/promptui"

	"github.com/segmentio/aws-okta/lib/client"
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
