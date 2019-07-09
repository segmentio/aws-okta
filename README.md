# aws-okta

`aws-okta` allows you to authenticate with AWS using your Okta credentials.

## Installing

If you have a functional go environment, you can install with:

```bash
$ go get github.com/segmentio/aws-okta
```

[See the wiki for more installation options like Linux packages and precompiled binaries.](https://github.com/segmentio/aws-okta/wiki/Installation)

### MacOS

You can install with `brew`:

```bash
$ brew install aws-okta
```

### Windows

See [docs/windows.md](docs/windows.md) for information on getting this working with Windows.

## Usage

### Adding Okta credentials

```bash
$ aws-okta add
```

This will prompt you for your Okta organization, custom domain, region, username, and password. These credentials will then be stored in your keyring for future use.

### Exec

```bash
$ aws-okta exec <profile> -- <command>
```

Exec will assume the role specified by the given aws config profile and execute a command with the proper environment variables set.  This command is a drop-in replacement for `aws-vault exec` and accepts all of the same command line flags:

```bash
$ aws-okta help exec
exec will run the command specified with aws credentials set in the environment

Usage:
  aws-okta exec <profile> -- <command>

Flags:
  -a, --assume-role-ttl duration   Expiration time for assumed role (default 15m0s)
  -h, --help                       help for exec
  -t, --session-ttl duration       Expiration time for okta role session (default 1h0m0s)

Global Flags:
  -b, --backend string   Secret backend to use [kwallet secret-service file] (default "file")
  -d, --debug            Enable debug logging
```

### Exec for EKS and Kubernetes

`aws-okta` can also be used to authenticate `kubectl` to your AWS EKS cluster. Assuming you have [installed `kubectl`](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html), [setup your kubeconfig](https://docs.aws.amazon.com/eks/latest/userguide/create-kubeconfig.html) and [installed `aws-iam-authenticator`](https://docs.aws.amazon.com/eks/latest/userguide/configure-kubectl.html), you can now access your EKS cluster with `kubectl`. Note that on a new cluster, your Okta CLI user needs to be using the same assumed role as the one who created the cluster. Otherwise, your cluster needs to have been configured to allow your assumed role.

```bash
$ aws-okta exec <profile> -- kubectl version --short
```

Likewise, most Kubernetes projects should work, like Helm and Ark.

```bash
$ aws-okta exec <profile> -- helm version --short
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

#### A more complex example

The `aws_saml_url` can be set in the "okta" ini section, or on a per profile basis. This is useful if, for example, your organization has several Okta Apps (i.e. one for dev/qa and one for prod, or one for internal use and one for integrations with third party providers). For example:

```ini
[okta]
# This is the "default" Okta App
aws_saml_url = home/amazon_aws/cuZGoka9dAIFcyG0UllG/214

[profile dev]
# This profile uses the default Okta app
role_arn = arn:aws:iam::<account-id>:role/<okta-role-name>

[profile integrations-auth]
# This is a distinct Okta App
aws_saml_url = home/amazon_aws/woezQTbGWUaLSrYDvINU/214
role_arn = arn:aws:iam::<account-id>:role/<okta-role-name>

[profile vendor]
# This profile uses the "integrations-auth" Okta app combined with secondary role assumption
source_profile = integrations-auth
role_arn = arn:aws:iam::<account-id>:role/<secondary-role-name>

[profile testaccount]
# This stores the Okta session in a separate item in the Keyring.
# This is useful if the Okta session is used or modified by other applications
# and needs to be isolated from other sessions. It is also useful for
# development versions or multiple versions of aws-okta running.
okta_session_cookie_key = okta-session-cookie-test
role_arn = arn:aws:iam::<account-id>:role/<okta-role-name>
```

The configuration above means that you can use multiple Okta Apps at the same time and switch between them easily.

#### Configuring Okta session and AWS assume role TTLs

The default TTLs for both Okta sessions and AWS assumed roles is 1 hour.  This means that aws-okta will re-authenticate to Okta and AWS credentials will expire every hour.  In addition to specifying the Okta session and AWS assume role TTLs with the command-line flags, they can be set using the `AWS_SESSION_TTL` and `AWS_ASSUME_ROLE_TTL` environment variables respectively.

```bash
export AWS_SESSION_TTL=1h
export AWS_ASSUME_ROLE_TTL=1h
```

The AWS assume role TTL can also be set per-profile in the aws config:

```ini
# example with a role that's configured with a max session duration of 12 hours
[profile ttldemo]
aws_saml_url = home/amazon_aws/cuZGoka9dAIFcyG0UllG/214
role_arn = arn:aws:iam::<account-id>:role/<okta-role-name>
assume_role_ttl = 12h
```

#### Multi-factor Authentication (MFA) configuration

If you have a single MFA factor configured, that factor will be automatically selected.  By default, if you have multiple available MFA factors, then you will be prompted to select which one to use.  However, if you have multiple factors and want to specify which factor to use, you can do one of the following:

* Specify on the command line with `--mfa-provider` and `--mfa-factor-type`
* Specify with environment variables `AWS_OKTA_MFA_PROVIDER` and `AWS_OKTA_MFA_FACTOR_TYPE`
* Specify in your aws config with `mfa_provider` and `mfa_factor_type`

## Backends

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_OKTA_BACKEND` environment variable.

For Linux / Ubuntu add the following to your bash config / zshrc etc:
```
export AWS_OKTA_BACKEND=secret-service
```

## --session-cache-single-item aka AWS_OKTA_SESSION_CACHE_SINGLE_ITEM (alpha)

This flag enables a new secure session cache that stores all sessions in the same keyring item. For macOS users, this means drastically fewer authorization prompts when upgrading or running local builds.

No provision is made to migrate sessions between session caches.

Implemented in [https://github.com/segmentio/aws-okta/issues/146](#146).

## Local Development

If you're developing in Linux, you'll need to get `libusb`. For Ubuntu, install the libusb-1.0-0-dev or use the `Dockerfile` provided in the repo.

## Running Tests

`make test`

## Releasing

Pushing a new tag will cause Circle to automatically create and push a linux release.  After this is done, you should run (from a mac):

```bash
$ export CIRCLE_TAG=`git describe --tags`
$ make release-mac
```

## Analytics

`aws-okta` includes some usage analytics code which Segment uses internally for tracking usage of internal tools.  This analytics code is turned off by default, and can only be enabled via a linker flag at build time, which we do not set for public github releases.

## Internals

### Authentication process

We use the following multiple step authentication:

- Step 1 : Basic authentication against Okta
- Step 2 : MFA challenge if required
- Step 3 : Get AWS SAML assertion from Okta
- Step 4 : Assume base okta role from profile with the SAML Assertion
- Step 5 : Assume the requested AWS Role from the targeted AWS account to generate STS credentials
