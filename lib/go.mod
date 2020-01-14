module github.com/segmentio/aws-okta/lib/v2

go 1.13

require (
	github.com/99designs/keyring v1.1.3
	github.com/aws/aws-sdk-go v1.26.8
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/marshallbrekka/go-u2fhost v0.0.0-20170128051651-72b0e7a3f583
	github.com/marshallbrekka/go.hid v0.0.0-20161227002717-2c1c4616a9e7 // indirect
	github.com/segmentio/kit v0.0.0-20191114232910-1ce35542129c
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/vitaminwater/cgo.wchar v0.0.0-20160320123332-5dd6f4be3f2a // indirect
	golang.org/x/net v0.0.0-20191007182048-72f939374954
	golang.org/x/text v0.3.2 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.4 // indirect
)

// oof https://github.com/99designs/keyring/issues/56#issuecomment-566256653
replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
