package lib

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func Prompt(prompt string, sensitive bool) (string, error) {
	return PromptWithOutput(prompt, sensitive, os.Stdout)
}

func PromptWithOutput(prompt string, sensitive bool, output *os.File) (string, error) {
	fmt.Fprintf(output, "%s: ", prompt)
	defer fmt.Fprintf(output, "\n")

	if sensitive {
		var input []byte
		input, err := terminal.ReadPassword(int(syscall.Stdin))
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
