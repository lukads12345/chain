# Build Geth in a stock Go builder container
FROM golang:1.20.4-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git bash

ADD . /go-ethereum
RUN cd /go-ethereum && make geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates curl jq tini
COPY --from=builder /go-ethereum/build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 8547 30303 30303/udp
ENTRYPOINT ["geth"]