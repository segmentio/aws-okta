package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func prompt(prompt string, sensitive bool) (string, error) {
	return promptWithOutput(prompt, sensitive, os.Stderr)
}

func promptWithOutput(prompt string, sensitive bool, output *os.File) (string, error) {
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
