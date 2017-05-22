package main

import (
	"os"

	"github.com/segmentio/conf"
	//log "github.com/sirupsen/logrus"
	"github.com/apex/log"
)

type cliConfig struct {
	Debug bool `conf:"debug" help:"Enable debug mode"`
}

func init() {
	if dl := os.Getenv("AWS_OKTA_DEBUG"); dl != "" {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	var err error
	loader := conf.Loader{
		Name: "aws-okta",
		Args: os.Args[1:],
		Commands: []conf.Command{
			{"login", "Login to Okta and store credentials to keystore"},
			{"export", "Export the temporary AWS credentials for a given profile"},
			{"exec", "Exec the given command with the temporary AWS credentials"},
			{"info", "Display information about given profile session"},
		},
	}

	cmdSig := make(chan os.Signal)
	switch cmd, args := conf.LoadWith(nil, loader); cmd {
	case "login":
		err = cmdLogin(args)
	case "export":
		log.Error("Command not implemented yet.")
	case "exec":
		err = cmdExec(args, cmdSig)
	case "info":
		err = cmdInfo(args)
	default:
		loader.PrintHelp(nil)
	}

	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}
