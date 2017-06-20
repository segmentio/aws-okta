package lib

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

func Prompt(prompt string, sensitive bool) (string, error) {
	fmt.Printf("%s: ", prompt)
	if sensitive {
		var input []byte
		input, err := terminal.ReadPassword(1)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(input)), nil
	}
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}
