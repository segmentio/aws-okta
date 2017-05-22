# AWS Okta

This is a work in progress CLI to use Okta as authentication provider.

We may at some point just add that into aws-vault and send a PR.

## Authentication process

We use a multiple steps authentication here :

- Step 1 : Basic authentication against Okta
- Step 2 : MFA challenge if required (Always required for us)
- Step 3 : Get AWS SAML assertion from Okta
- Step 4 : Assume a first AWS Role with the SAML Assertion. Here we assume a role from the Ops account.
- Step 5 : Assume a second AWS Role from the targeted AWS account (dev, stage or production) to get temporary credentials

## Usage

Get the CLI :

```
go get github.com/segmentio/aws-okta/cmd/aws-okta
```

Authenticate against Okta and get your AWS creds :

```
aws-okta login <profile_name>
```

Exec `aws s3 ls` using your temporary AWS credentials :

```
aws-okta exec <profile_name> -- aws s3 ls
```

Right now the keystore is only used to store the username/password for the Okta authentication. Once all the features are working properly we will also store the AWS credentials there.

Export your temporary AWS credentials into the current shell environment :

```
aws-okta export <profile_name>
```
