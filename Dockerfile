FROM golang:1.11 as build

ENV SRC github.com/segmentio/aws-okta
ARG VERSION

WORKDIR /build
COPY . /go/src/${SRC}

RUN apt-get update && apt-get install --no-install-recommends -y \
    libusb-1.0-0-dev \
    ca-certificates \
    build-essential \
    git

RUN CGO_ENABLED=1 go build -o aws-okta -ldflags="-X main.version=$VERSION" ${SRC}/cmd

##################################################

FROM scratch
COPY --from=build /build/aws-okta /
ENTRYPOINT ["/aws-okta"]
