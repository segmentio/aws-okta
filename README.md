# aws-keycloak

`aws-keycloak` allows you to authenticate with AWS using your Keycloak credentials.

## Installing

You can install with:

```bash
$ go get github.com/mulesoft-labs/aws-keycloak
```

## Usage

`aws-keycloak --` behaves just like `aws`, except that it may ask for keycloak credentials if it can't find any in the keychain.

```bash
$ aws-keycloak -- <command>
```

After authenticating to Keycloak, user will be presented with the roles available across all AWS accounts. User can also select a role with `--profile`.

```bash
aws-keycloak allows you to authenticate with AWS using your keycloak credentials

Usage:
  aws-keycloak [flags] -- <aws command>
  aws-keycloak [command]

Examples:
  aws-keycloak -p power-devx -- sts get-caller-identity

Available Commands:
  check       Check will authenticate you through keycloak and store session.
  help        Help about any command

Flags:
  -b, --backend string            Secret backend to use [keychain file]
  -c, --config string             Keycloak provider configuration (default "/.aws/keycloak-config")
  -d, --debug                     Enable debug logging
  -h, --help                      help for aws-keycloak
  -k, --keycloak-profile string   Keycloak system to auth to (default "id")
  -p, --profile string            AWS profile to run against (optional)

Use "aws-keycloak [command] --help" for more information about a command.
```

### Configuring

You need a configuration file that describes how to talk to the keycloak server. This is an ini file at `~/.aws/keycloak-config`, or can be specified using `--config`.

The default keycloak profile is `id`. This can be specified with the `--keycloak-profile` flag. The section must contain:
```ini
[id]
keycloak_base = https://keycloak
aws_saml_path = /auth/realms/<realm>/protocol/saml/clients/amazon-aws
aws_oidc_path = /auth/realms/<realm>/protocol/openid-connect/token
aws_client_id = urn:amazon:webservices
aws_client_secret = <client secret from keycloak>
```

## Backends

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_OKTA_BACKEND` environment variable.
