# Goals:
# - user can build binaries on their system without having to install special tools
# - user can fork the canonical repo and expect to be able to run CircleCI checks
#
# This makefile is meant for humans

VERSION := $(shell git describe --tags --always --dirty="-dev")
LDFLAGS := -ldflags='-X "main.Version=$(VERSION)"'

test: | govendor
	govendor sync
	go test -v ./...

all: dist/aws-okta-$(VERSION)-darwin-amd64 dist/aws-okta-$(VERSION)-linux-amd64

container-build: dist/aws-okta-$(VERSION)-linux-amd64

clean:
	rm -rf ./dist

dist/:
	mkdir -p dist

dist/aws-okta-$(VERSION)-darwin-amd64: | govendor dist/
	govendor sync
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $@

dist/aws-okta-$(VERSION)-linux-amd64: | govendor dist/
	govendor sync
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $@

dist/aws-okta-$(VERSION)-win-amd64: | govendor dist/
	govendor sync
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $@

govendor:
	go get -u github.com/kardianos/govendor

.PHONY: clean all govendor container-build
