package okta

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

func Prompt(prompt string, sensitive bool) (value string, err error) {
	fmt.Printf("%s: ", prompt)
	if sensitive {
		var input []byte
		input, err = terminal.ReadPassword(1)
		if err != nil {
			return
		}
		value = string(input)
	} else {
		reader := bufio.NewReader(os.Stdin)
		value, err = reader.ReadString('\n')
		if err != nil {
			return
		}
	}

	return
}
