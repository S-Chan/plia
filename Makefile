.PHONY: build cli install_deps

.DEFAULT_GOAL := build

build: cli
	@:

cli: install_deps
	go build -o out/plio -v ./cmd

install_deps:
	go get -v ./...
