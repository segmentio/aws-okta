// Package useragent provides an extension to the go default User-Agent string
// including OS/Architecture by default and allowing you to easily add more
// detail about your specific client.
package useragent

import (
	"bufio"
	"bytes"
	"net/http"
	"os/exec"
	"strings"
)

// UserAgent is the structure we use to store our user agent string information
type UserAgent struct {
	Base,
	Architecture string
	Additional []string
}

// DefaultUserAgent is a default user agent
var DefaultUserAgent = UserAgent{
	Base:         defaultHTTPClientUserAgent(),
	Architecture: currentArchitecture(),
}

// NewUserAgent returns a new UserAgent with the additionals specified
func NewUserAgent(additional ...string) *UserAgent {
	newagent := DefaultUserAgent
	newagent.Additional = additional
	return &newagent
}

// String implements Stringer interface
func (agent *UserAgent) String() string {
	out := agent.Base + " "
	out = out + "(" + agent.Architecture + ")"
	for _, additional := range agent.Additional {
		out = out + " " + additional
	}
	return out
}

// This is here to allow testing on non windows platform
func parseWindowsVersion(ver string) string {
	// split the version string into fields by whitespace
	fields := strings.Fields(ver)
	val := fields[0]
	os := "Windows"
	// Old versions of Windows just output a version here.
	if len(fields) > 3 {
		os = "Windows NT"
		val = fields[3]
	}
	// the last split contains junk we don't want
	parts := strings.SplitN(val, ".", 3)
	return os + " " + parts[0] + "." + parts[1]
}

// convenience wrapper for system() like functionality

// run executs a commnd and returns stdout as an array of strings by line
func run(command string, parameters ...string) ([]string, error) {
	cmd := exec.Command(command, parameters...)
	output, err := cmd.Output()
	if err == nil {
		result := []string{}
		// line scanning is default behavior
		lineScanner := bufio.NewScanner(bytes.NewReader(output))
		lineScanner.Split(bufio.ScanLines)
		for lineScanner.Scan() {
			result = append(result, lineScanner.Text())
		}
		return result, nil
	}
	// err is returned if the command was unsuccessful
	return nil, err
}

// defaultHTTPClientUserAgent loops back a request through a buffer so that we can extract the
// private default UserAgent from Go
func defaultHTTPClientUserAgent() string {
	// I could use an empty string for the first 2 arguments, but that behavior could change
	req, _ := http.NewRequest("GET", "/", nil)
	out := bytes.Buffer{}
	err := req.Write(&out)
	if err != nil {
		// something very funky happened if we got an error
		panic(err)
	}
	// then read the request back
	req, _ = http.ReadRequest(bufio.NewReader(&out))
	// and finally return the user agent.
	return req.Header.Get("User-Agent")
}
