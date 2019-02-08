FROM golang:1.9-stretch AS builder
WORKDIR /go/src/github.com/segmentio/aws-okta
RUN apt-get update && apt-get -y install libusb-dev  libusb-1.0-0-dev && pkg-config --cflags --libs libusb-1.0
COPY . .
RUN make linux

FROM debian:stretch-slim
WORKDIR /app/
RUN apt-get update && apt-get -y install libusb-1.0-0 ca-certificates python-pip && pip install awscli
COPY --from=builder /go/src/github.com/segmentio/aws-okta/dist/aws-okta-*-linux-amd64 /app/aws-okta
RUN useradd -u 10001 scratchuser
USER scratchuser
ENTRYPOINT ["/app/aws-okta"]
