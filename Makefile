.PHONY: build cli server install_deps

.DEFAULT_GOAL := build

build: install_deps cli server
	@:

cli: install_deps
	go build -o out/plio -v ./cmd

server: install_deps
	go build -o out/server -v ./server

install_deps:
	go get -v ./...
