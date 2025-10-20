SHELL := /bin/bash

.PHONY: fmt lint build test run docker

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

build:
	cargo build --workspace

test:
	cargo test --workspace

run:
	cargo run -p secrets-broker

docker:
	docker build -f deploy/Dockerfile.broker -t secrets-broker:dev .
