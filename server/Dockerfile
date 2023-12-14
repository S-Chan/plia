FROM golang:1.21 AS build
WORKDIR /go/src
COPY . .
RUN make server
ENTRYPOINT ["/go/src/out/server"]
