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
$ aws-keycloak help

Usage:
  aws-keycloak [command]

Available Commands:
  help        Help about any command
  login       login will authenticate you through keycloak and store session (a way to test that your credentials work).

Flags:
  -b, --backend string            Secret backend to use [keychain file]
  -d, --debug                     Enable debug logging
  -h, --help                      help for aws-keycloak
  -k, --keycloak-profile string   Keycloak system to auth to (default "id")
  -p, --profile string            AWS profile to run against (optional)

Use "aws-keycloak [command] --help" for more information about a command.
```


### Configuring your aws config

`aws-okta` assumes that your base role is one that has been configured for Okta's SAML integration by your Okta admin. Okta provides a guide for setting up that integration [here](https://support.okta.com/help/servlet/fileField?retURL=%2Fhelp%2Farticles%2FKnowledge_Article%2FAmazon-Web-Services-and-Okta-Integration-Guide&entityId=ka0F0000000MeyyIAC&field=File_Attachment__Body__s).  During that configuration, your admin should be able to grab the AWS App Embed URL from the General tab of the AWS application in your Okta org.  You will need to set that value in your `~/.aws/config` file, for example:

```ini
[okta]
aws_saml_url = home/amazon_aws/0ac4qfegf372HSvKF6a3/965
```

Next, you need to set up your base Okta role.  This will be one your admin created while setting up the integration.  It should be specified like any other aws profile:

```ini
[profile okta-dev]
role_arn = arn:aws:iam::<account-id>:role/<okta-role-name>
region = <region>
```

Your setup may require additional roles to be configured if your admin has set up a more complicated role scheme like cross account roles.  For more details on the authentication process, see the internals section.

## Backends

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_OKTA_BACKEND` environment variable.

## Releasing

Pushing a new tag will cause Circle to automatically create and push a linux release.  After this is done, you shoule run (from a mac):

```bash
$ export CIRCLE_TAG=`git describe --tags`
$ make release-mac
```

## Internals

### Authentication process

We use the following multiple step authentication:

- Step 1 : Basic authentication against Okta
- Step 2 : MFA challenge if required
- Step 3 : Get AWS SAML assertion from Okta
- Step 4 : Assume base okta role from profile with the SAML Assertion
- Step 5 : Assume the requested AWS Role from the targeted AWS account to generate STS credentials
