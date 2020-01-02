module github.com/segmentio/aws-okta/v2

require (
	github.com/99designs/keyring v1.1.3
	github.com/keybase/go-keychain v0.0.0-20191220220820-f65a47cbe0b1 // indirect
	github.com/mitchellh/go-homedir v1.1.0

	github.com/segmentio/analytics-go v3.0.1+incompatible
	github.com/segmentio/aws-okta/v2/lib v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.0-20170621173259-31694f19adee
	github.com/vaughan0/go-ini v0.0.0-20130923145212-a98ad7ee00ec
	golang.org/x/crypto v0.0.0-20191219195013-becbf705a915
	golang.org/x/sys v0.0.0-20191220220014-0732a990476f // indirect
)

go 1.13

// TODO: remove? not really sure why this is necessary
replace github.com/segmentio/aws-okta/v2/lib => ./lib

// TODO: temp until oktaclient/mfa are replaced
replace github.com/segmentio/aws-okta => ../

// oof https://github.com/99designs/keyring/issues/56#issuecomment-566256653
replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
