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

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_KEYCLOAK_BACKEND` environment variable.

#### Examples

```bash
$ aws-keycloak check
Enter username/password for keycloak (env: id)
Username: chris.byron
Password:
[  0] arn:aws:iam::003617316831:role/keycloak-admin-identity
[  1] arn:aws:iam::906852541812:role/keycloak-power-stgxdr
[  2] arn:aws:iam::055970264539:role/keycloak-admin-sandbox
[  3] arn:aws:iam::732333100769:role/keycloak-ro-build
[  4] arn:aws:iam::053047940888:role/keycloak-power-kdev
[  5] arn:aws:iam::055970264539:role/keycloak-power-sandbox
[  6] arn:aws:iam::675448719222:role/keycloak-power-kqa
[  7] arn:aws:iam::700982990415:role/keycloak-power-kstg
[  8] arn:aws:iam::645983395287:role/keycloak-power-stgx
[  9] arn:aws:iam::073815667418:role/keycloak-power-devx
[ 10] arn:aws:iam::008119339527:role/keycloak-power-qax
Choice: 9
Assuming role 'power-devx'
  You can specify this role with the --profile flag if you also put it in your aws config.
  Run `aws --profile power-devx configure` and don't enter any Key ID or Secret Key.
```

```bash
$ aws-keycloak --debug --profile power-devx check
DEBU[0000] Parsing config file /Users/chrisbyron/.aws/keycloak-config
DEBU[0000] Step 0: Checking existing AWS session
DEBU[0000] found aws session in keyring
DEBU[0000] AWS session already valid for power-devx
```

```bash
$ aws-keycloak -p power-devx -- sts get-caller-identity
WARN[0003] --profile argument expects aws config to already exist so it can use the default region.
WARN[0003] Use `aws configure --profile power-devx`
WARN[0003]   but leave Access Key and Secret blank.
WARN[0003] Continuing without aws profile.
{
    "UserId": "AROAIC5ECYBOX4KG2CIK4:chris.byron",
    "Account": "073815667418",
    "Arn": "arn:aws:sts::073815667418:assumed-role/keycloak-power-devx/chris.byron"
}

$ aws configure --profile power-devx
AWS Access Key ID [None]:
AWS Secret Access Key [None]:
Default region name [None]: us-east-1
Default output format [None]:

$ aws-keycloak -p power-devx -- sts get-caller-identity
{
    "UserId": "AROAIC5ECYBOX4KG2CIK4:chris.byron",
    "Account": "073815667418",
    "Arn": "arn:aws:sts::073815667418:assumed-role/keycloak-power-devx/chris.byron"
}
```
