package oktaclient

type Creds struct {
	Username string
	Password string
}

type Client struct {
	Creds  Creds
	Domain string
}

func (c *Client) ValidateCredentials() error {
	return c.DoAuth()
}

func (c *Client) DoAuth() error {
	// TODO
	return nil
}
