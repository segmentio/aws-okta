FROM golang:1.13 as build

ARG VERSION

WORKDIR /build
COPY . /src

RUN apt-get update && apt-get install --no-install-recommends -y \
    libusb-1.0-0-dev \
    ca-certificates \
    build-essential \
    git

RUN CGO_ENABLED=1 go build -o aws-okta -ldflags="-X main.version=$VERSION" /src/cmd

FROM scratch
COPY --from=build /build/aws-okta /
ENTRYPOINT ["/aws-okta"]
