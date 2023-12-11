.PHONY: build install_deps

.DEFAULT_GOAL := build

build: install_deps
	go build -o out/plio -v ./cmd

install_deps:
	go get -v ./...
