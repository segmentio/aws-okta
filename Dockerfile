from golang:1.12 as build

ENV SRC github.com/segmentio/aws-okta
ARG VERSION

RUN apt-get update
RUN apt-get install --no-install-recommends -y \
    libusb-1.0-0-dev \
    ca-certificates \
    build-essential \
    git

WORKDIR /src
COPY . .

RUN go mod download 
RUN CGO_ENABLED=1 GOOS=linux go build -o /aws-okta -ldflags="-X main.version=$VERSION"

FROM golang:1.12 as debug
COPY --from=build /aws-okta /usr/local/bin/aws-okta
RUN apt-get update && \
    apt-get install --no-install-recommends -y \
    libusb-1.0-0 \
    ca-certificates
ENTRYPOINT ["/usr/local/bin/aws-okta"]

FROM scratch as production
COPY --from=build /aws-okta /aws-okta
ENTRYPOINT ["/aws-okta"]

