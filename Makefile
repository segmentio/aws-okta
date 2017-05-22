runstage:
	@go run cmd/aws-okta/*.go ${CMD} -profile stage

build:
	go build -o aws-okta cmd/aws-okta/*.go
