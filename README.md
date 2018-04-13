# aws-keycloak

`aws-keycloak` allows you to authenticate with AWS using your Keycloak credentials. It runs any commands with the 3 AWS euth nvironment variables set.
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
```

## Installing

You can install with:

```
$ go get github.com/mulesoft-labs/aws-keycloak
```

## Usage

```
aws-keycloak allows you to authenticate with AWS using your keycloak credentials

$aws-keycloak --help
aws-keycloak allows you to authenticate with AWS using your keycloak credentials

Usage:
  aws-keycloak [flags] -- <command>
  aws-keycloak [command]

Examples:
  aws-keycloak -p power-devx -- aws sts get-caller-identity

Available Commands:
  aws         Invoke aws subcommands (always use -- before subcommand and flags)
  check       Check will authenticate you through keycloak and store session.
  env         Invokes `printenv`. Takes var names or prints all env
  help        Help about any command

Flags:
  -b, --backend string            Secret backend to use [keychain file]
  -c, --config string             Keycloak provider configuration (default "/.aws/keycloak-config")
  -d, --debug                     Enable debug output
  -h, --help                      help for aws-keycloak
  -k, --keycloak-profile string   Keycloak system to auth to (default "id")
  -p, --profile string            AWS profile to run against (recommended)
  -q, --quiet                     Minimize output
      --version                   version for aws-keycloak

Use "aws-keycloak [command] --help" for more information about a command.
```

`aws-keycloak --` sets 3 (or 4 if `AWS_DEFAULT_REGION` is set) environment vars and runs the command that comes after it.

```
$ aws-keycloak -- printenv
AWS_ACCESS_KEY_ID=ASIAJWCS7CRTZC3XTQ4A
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_SESSION_TOKEN=xxxxxxxxxxxxxxxxxxxx....
```

`aws-keycloak` also has some helper subcommands for the `aws` CLI tool and getting env vars.
```
$ aws-keycloak -- printenv [name]
 # is the same as
$ aws-keycloak env [name]

$ aws-keycloak -- aws <subcomand>
 # is the same as
$ aws-keycloak aws -- <subcomand>

$ aws-keycloak check
 # is the same as
$ aws-keycloak -- aws sts get-caller-identity
```

When invoked, user will be asked to authenticate to keycloak and will be prompted with the roles available across all AWS accounts. To avoid this, use the `--profile` flag.
```
$ aws-keycloak -p power-devx check
 # this will not prompt for role
```

### Configuring

You need a configuration file that describes how to talk to the keycloak server. This is an ini file at `~/.aws/keycloak-config`, or can be specified using `--config`.

The default keycloak profile is `id`. This can be specified with the `--keycloak-profile` flag. The section must contain:
```ini
[id]
keycloak_base = https://keycloak
aws_client_id = urn:amazon:webservices
aws_client_secret = <client secret from keycloak>
```

## Backends

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_KEYCLOAK_BACKEND` environment variable.

### Examples

```
$aws-keycloak check
INFO[0000] If browser window does not open automatically, open it by clicking on the link:
 https://keycloak.prod.identity.msap.io/auth/realms/Mulesoft/protocol/openid-connect/auth?client_id=urn%3Aamazon%3Awebservices&redirect_uri=http%3A%2F%2F127.0.0.1%3A55451%2Fcallback&response_type=code&state=3mZh2vR7
INFO[0000] Waiting for response on: http://127.0.0.1:55451
INFO[0024] Successfully exchanged for Access Token
[  0] arn:aws:iam::003617316831:role/keycloak-admin-identity
[  1] arn:aws:iam::008119339527:role/keycloak-power-qax
[  2] arn:aws:iam::053047940888:role/keycloak-power-kdev
[  3] arn:aws:iam::055970264539:role/keycloak-power-sandbox
[  4] arn:aws:iam::073815667418:role/keycloak-power-devx
[  5] arn:aws:iam::379287829376:role/keycloak-power-kprod
[  6] arn:aws:iam::494141260463:role/keycloak-power-prod
[  7] arn:aws:iam::645983395287:role/keycloak-power-stgx
[  8] arn:aws:iam::655988475869:role/keycloak-power-prod-eu-rt
[  9] arn:aws:iam::675448719222:role/keycloak-power-kqa
Choice: 4
INFO[0034] Assuming role 'power-devx'. You can specify this with the --profile flag
{
    "UserId": "AROAIC5ECYBOX4KG2CIK4:chris.byron",
    "Account": "073815667418",
    "Arn": "arn:aws:sts::073815667418:assumed-role/keycloak-power-devx/chris.byron"
}
```

```
$aws-keycloak --debug --profile power-devx check
DEBU[0000] Parsing config file /Users/chrisbyron/.aws/keycloak-config
DEBU[0000] Step 0: Checking existing AWS session
DEBU[0000] found aws session in keyring
DEBU[0000] AWS session already valid for power-devx
DEBU[0000] Running command `aws sts get-caller-identity` with AWS env vars set
{
    "UserId": "AROAIC5ECYBOX4KG2CIK4:chris.byron",
    "Account": "073815667418",
    "Arn": "arn:aws:sts::073815667418:assumed-role/keycloak-power-devx/chris.byron"
}
```

```
$aws-keycloak -p power-devx aws -- sts get-caller-identity
{
    "UserId": "AROAIC5ECYBOX4KG2CIK4:chris.byron",
    "Account": "073815667418",
    "Arn": "arn:aws:sts::073815667418:assumed-role/keycloak-power-devx/chris.byron"
}

$ export KEY_ID=$(aws-keycloak -p power-devx env AWS_ACCESS_KEY_ID)
$ echo $KEY_ID
ASIAJWCS7CRTZC3XTQ4A
```
