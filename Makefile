# Goals:
# - user can build binaries on their system without having to install special tools
# - user can fork the canonical repo and expect to be able to run CircleCI checks
#
# This makefile is meant for humans

VERSION := $(shell git describe --tags --always --dirty="-dev")
LDFLAGS := -ldflags='-X "main.Version=$(VERSION)"'

test:
	GO111MODULE=on go test -mod=vendor -covermode=count -coverprofile=coverage.out -v ./...
	@echo
	@echo INFO: to launch the coverage report: go tool cover -html=coverage.out
##
## More information about cover reports:
## https://blog.golang.org/cover

staticcheck:
	go vet
	staticcheck cmd/*.go
	staticcheck lib/client/*.go
	staticcheck lib/client/mfa/*.go
	staticcheck lib/provider/*.go

sec-lib:
	gosec lib/provider/
	gosec lib/client/

sec-cli:
	gosec cmd/

all: linux darwin
linux: dist/aws-okta-$(VERSION)-linux-amd64
darwin: dist/aws-okta-$(VERSION)-darwin-amd64

clean:
	rm -rf ./dist
	rm -f coverage.out

dist/:
	mkdir -p dist

dist/aws-okta-$(VERSION)-darwin-amd64: | dist/
	GOOS=darwin GOARCH=amd64 GO111MODULE=on go build -mod=vendor $(LDFLAGS) -o $@

dist/aws-okta-$(VERSION)-linux-amd64: | dist/
	GOOS=linux GOARCH=amd64 GO111MODULE=on go build -mod=vendor $(LDFLAGS) -o $@

.PHONY: clean all linux darwin test
