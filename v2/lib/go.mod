module github.com/segmentio/aws-okta/v2/lib

go 1.13

require (
	github.com/aws/aws-sdk-go v1.26.8
	github.com/segmentio/aws-okta v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/net v0.0.0-20191007182048-72f939374954
)

// TODO: temp
replace github.com/segmentio/aws-okta => ../..
