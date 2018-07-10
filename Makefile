GOCMD=go
GOBUILD=$(GOCMD) build
GOINSTALL=$(GOCMD) install
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=aws-keycloak

.PHONY: all
all: dep test build

.PHONY: dep
dep:
	dep ensure

.PHONY: build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v

.PHONY: test
test:
	$(GOTEST) -v ./...

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
