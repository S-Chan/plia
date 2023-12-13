.PHONY: build cli server install_deps

.DEFAULT_GOAL := build

build: install_deps cli server
	@:

cli: install_deps
	go build -o out/plio -v ./cmd

server: install_deps
	CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o out/server -v ./server

install_deps:
	go get -v ./...
