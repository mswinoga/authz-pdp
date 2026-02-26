GOPATH := $(shell go env GOPATH)
PROTOC_INCLUDE := $(shell brew --prefix protobuf)/include

.PHONY: generate build test lint

generate:
	protoc \
		--proto_path=pdp/proto \
		--proto_path=$(PROTOC_INCLUDE) \
		--go_out=pdp/gen/pdp \
		--go_opt=paths=source_relative \
		pdp/proto/model.proto

build:
	go build ./...

test:
	go test ./...

lint:
	go vet ./...
