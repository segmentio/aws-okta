module github.com/segmentio/aws-okta/lib/v2

go 1.13

require (
	github.com/99designs/keyring v1.1.3
	github.com/aws/aws-sdk-go v1.26.8
	github.com/karalabe/hid v1.0.0 // indirect
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/marshallbrekka/go-u2fhost v0.0.0-20200114212649-cc764c209ee9
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/net v0.0.0-20191007182048-72f939374954
	golang.org/x/sys v0.0.0-20190922100055-0a153f010e69 // indirect
	golang.org/x/text v0.3.2 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.4 // indirect
)

// oof https://github.com/99designs/keyring/issues/56#issuecomment-566256653
replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
