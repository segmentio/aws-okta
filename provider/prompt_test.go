package provider_test

import (
	"testing"

	"github.com/mulesoft-labs/aws-keycloak/provider"
)

func TestPrompt(t *testing.T) {
	inputBuffer.Reset()
	inputBuffer.Write([]byte("input\n"))

	capture, err := provider.Prompt("test string", false)
	if err != nil {
		t.Errorf("Got unexpected error from prompt: %s", err)
	}
	if capture != "input" {
		t.Errorf("Got unexpected input from prompt: %s", capture)
	}
}

type multiTest struct {
	name    string
	choices []string
	input   string
	sel     string
	n       int
}

func TestPromptMulti(t *testing.T) {
	tests := []multiTest{
		multiTest{
			name: "none",
			sel:  "error",
			n:    -1,
		},
		multiTest{
			name:    "one",
			choices: []string{"only"},
			sel:     "only",
			n:       0,
		},
		multiTest{
			name:    "many",
			choices: []string{"one", "two", "three"},
			input:   "1\n",
			sel:     "two",
			n:       1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputBuffer.Reset()
			inputBuffer.Write([]byte(tc.input))
			sel, n := provider.PromptMulti(tc.choices)
			if sel != tc.sel {
				t.Errorf("Unexpected selection returned: %s (expected %s)", sel, tc.sel)
			}
			if n != tc.n {
				t.Errorf("Unexpected selection number returned: %d (expected %d)", n, tc.n)
			}
		})
	}
}

func TestPromptMultiMatch(t *testing.T) {
	match := func(c string) bool {
		return c == "yes"
	}

	tests := []multiTest{
		multiTest{
			name:    "one",
			choices: []string{"only"},
			sel:     "only",
			n:       0,
		},
		multiTest{
			name:    "nomatch",
			choices: []string{"one", "two", "three"},
			input:   "1\n",
			sel:     "two",
			n:       1,
		},
		multiTest{
			name:    "match",
			choices: []string{"one", "yes", "three"},
			sel:     "yes",
			n:       1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputBuffer.Reset()
			inputBuffer.Write([]byte(tc.input))
			sel, n := provider.PromptMultiMatch(tc.choices, match)
			if sel != tc.sel {
				t.Errorf("Unexpected selection returned: %s (expected %s)", sel, tc.sel)
			}
			if n != tc.n {
				t.Errorf("Unexpected selection number returned: %d (expected %d)", n, tc.n)
			}
		})
	}
}

func TestPromptMultiMatchRole(t *testing.T) {
	tests := []multiTest{
		multiTest{
			name:    "one",
			choices: []string{"role/keycloak-only"},
			sel:     "only",
			n:       0,
		},
		multiTest{
			name:    "nomatch",
			choices: []string{"one", "role/keycloak-two", "three"},
			input:   "1\n",
			sel:     "two",
			n:       1,
		},
		multiTest{
			name:    "match",
			choices: []string{"one", "role/keycloak-match", "three"},
			sel:     "match",
			n:       1,
		},
		multiTest{
			name:    "keycloak-match",
			choices: []string{"one", "role/keycloak-match", "three"},
			sel:     "match",
			n:       1,
		},
		multiTest{
			name:    "end",
			choices: []string{"role/keycloak-x-end", "role/keycloak-end-x", "role/keycloak-end"},
			sel:     "end",
			n:       2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inputBuffer.Reset()
			inputBuffer.Write([]byte(tc.input))
			sel, n := provider.PromptMultiMatchRole(tc.choices, tc.name)
			if sel != tc.sel {
				t.Errorf("Unexpected selection returned: %s (expected %s)", sel, tc.sel)
			}
			if n != tc.n {
				t.Errorf("Unexpected selection number returned: %d (expected %d)", n, tc.n)
			}
		})
	}
}
