# aws-keycloak
`aws-keycloak` allows you to authenticate with AWS using your Keycloak credentials. It runs any commands with the 5 AWS environment variables set.
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
AWS_DEFAULT_REGION
AWS_REGION
```

## Installing
```
$ brew tap mulesoft-labs/tap
$ brew install aws-keycloak
```

### From source
```
$ go get github.com/mulesoft-labs/aws-keycloak
```

## Usage
```
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
  open        Open a AWS console logged into a given profile

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

`aws-keycloak --` sets 5 environment vars and runs the command that comes after it.

```
$ aws-keycloak -- printenv
AWS_ACCESS_KEY_ID=ASIAJWXXXXXXXX3XTQ4A
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_SESSION_TOKEN=xxxxxxxxxxxxxxxxxxxx....
AWS_DEFAULT_REGION=us-east-1
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

## Configuring

You need a configuration file that describes how to talk to the keycloak server. This is an ini file at `~/.aws/keycloak-config`, or can be specified using `--config`.

The default keycloak profile is `id`. This can be specified with the `--keycloak-profile` flag. The section must contain:
```ini
[id]
keycloak_base = https://keycloak
aws_client_id = urn:amazon:webservices
aws_client_secret = <client secret from keycloak>
```

## Aliases

Within the keycloak config file (above) you can specify aliases to shorten the commands you use. Aliases take the form `alias = keycloak-env:profile:region(optional)`.
```
[aliases]
stg     = id:admin-staging:us-west-2
build   = id:ro-build
sbox    = id.dev:power-sbox:us-west-1
```
Aliases are invoked with the `--profile|-p` param.
```
$ aws-keycloak -p stg check
{
    "UserId": "AROAXXXXXXXXXXXXXU752:tobias.funke",
    "Account": "003XXXXXX831",
    "Arn": "arn:aws:sts::003XXXXXX831:assumed-role/keycloak-admin-staging/tobias.funke"
}
```

## Backends

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_KEYCLOAK_BACKEND` environment variable.

### Examples

```
$aws-keycloak check
INFO[0000] If browser window does not open automatically, open it by clicking on the link:
 https://keycloak/auth/realms/Company/protocol/openid-connect/auth?client_id=urn%3Aamazon%3Awebservices&redirect_uri=http%3A%2F%2F127.0.0.1%3A55451%2Fcallback&response_type=code&state=3XXXXXX7
INFO[0000] Waiting for response on: http://127.0.0.1:55451
INFO[0024] Successfully exchanged for Access Token
[  0] arn:aws:iam::003XXXXXX831:role/keycloak-admin-acct1
[  1] arn:aws:iam::008XXXXXX527:role/keycloak-power-acct2
[  2] arn:aws:iam::053XXXXXX888:role/keycloak-power-acct3
[  3] arn:aws:iam::055XXXXXX539:role/keycloak-power-acct4
[  4] arn:aws:iam::073XXXXXX418:role/keycloak-power-acct5
[  5] arn:aws:iam::379XXXXXX376:role/keycloak-power-acct6
[  6] arn:aws:iam::494XXXXXX463:role/keycloak-power-acct7
[  7] arn:aws:iam::645XXXXXX287:role/keycloak-power-acct9
[  8] arn:aws:iam::655XXXXXX869:role/keycloak-power-acct10
[  9] arn:aws:iam::675XXXXXX222:role/keycloak-power-acct11
Choice: 4
INFO[0034] Assuming role 'power-acct1'. You can specify this with the --profile flag
{
    "UserId": "AROAXXXXXXXXXXXXXCIK4:tobias.funke",
    "Account": "073XXXXXX418",
    "Arn": "arn:aws:sts::073XXXXXX418:assumed-role/keycloak-power-acct1/tobias.funke"
}
```

```
$aws-keycloak --debug --profile power-acct1 check
DEBU[0000] Parsing config file /Users/tobias.funke/.aws/keycloak-config
DEBU[0000] Step 0: Checking existing AWS session
DEBU[0000] found aws session in keyring
DEBU[0000] AWS session already valid for power-acct1
DEBU[0000] Running command `aws sts get-caller-identity` with AWS env vars set
{
    "UserId": "AROAIC5ECYBOX4KG2CIK4:tobias.funke",
    "Account": "073XXXXXX418",
    "Arn": "arn:aws:sts::073XXXXXX418:assumed-role/keycloak-power-acct1/tobias.funke"
}
```

```
$aws-keycloak -p power-acct1 aws -- sts get-caller-identity
{
    "UserId": "AROAXXXXXXXXXXXXXCIK4:tobias.funke",
    "Account": "073XXXXXX418",
    "Arn": "arn:aws:sts::073XXXXXX418:assumed-role/keycloak-power-acct1/tobias.funke"
}

$ export KEY_ID=$(aws-keycloak -p power-acct1 env AWS_ACCESS_KEY_ID)
$ echo $KEY_ID
ASIAXXXXXXXXXXXXTQ4A
```
