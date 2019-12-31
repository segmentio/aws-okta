package analytics

import (
	"log"

	analytics "github.com/segmentio/analytics-go"
)

// Client is a convenience wrapper an analytics-go Client. A zero value
// client will no-op all its methods
type Client struct {
	client analytics.Client

	// global properties
	UserId         string
	KeyringBackend string
	Version        string
}

// New creates a new Client. Global properties should be set on returned Client.
func New(writeKey string) Client {
	cl, _ := analytics.NewWithConfig(writeKey, analytics.Config{
		BatchSize: 1,
	})
	return Client{
		client: cl,
	}
}

const (
	// TODO(nick): verify these fit best practices (casing, etc.)
	TraitVersion = "aws-okta-version"
	// TODO(nick): not clear the difference between a track trait
	// and a event property
	PropertyVersion        = "aws-okta-version"
	PropertyKeyringBackend = "backend"

	EventRanCommand     = "Ran Command"
	PropertyCommandName = "command"
	PropertyProfileName = "profile"
)

var AllProperties = map[string]struct{}{
	PropertyVersion:        struct{}{},
	PropertyKeyringBackend: struct{}{},
	PropertyCommandName:    struct{}{},
	PropertyProfileName:    struct{}{},
}

func (a Client) Identify() {
	if a.client == nil {
		return
	}
	a.client.Enqueue(analytics.Identify{
		UserId: a.UserId,
		Traits: analytics.NewTraits().
			Set(TraitVersion, a.Version),
	})
}

func (a Client) TrackRanCommand(commandName string, extraProps ...[2]string) {
	if a.client == nil {
		return
	}
	props := analytics.NewProperties().
		Set(PropertyKeyringBackend, a.KeyringBackend).
		Set(PropertyVersion, a.Version).
		Set(PropertyCommandName, commandName)
	for _, p := range extraProps {
		k := p[0]
		v := p[1]

		if _, ok := AllProperties[k]; !ok {
			log.Fatalf("invalid analytics property %s", k)
		}
		props.Set(k, v)
	}
	a.client.Enqueue(analytics.Track{
		UserId:     a.UserId,
		Event:      EventRanCommand,
		Properties: props,
	})
}

func (a Client) Close() {
	if a.client == nil {
		return
	}
	a.client.Close()
}
