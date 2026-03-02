GOPATH  := $(shell go env GOPATH)
BINARY     := bin/pdp-server
IMAGE      := authz-pdp:latest
BASE_IMAGE ?= busybox:latest
GOARCH  ?= amd64

# Detect protobuf include path: brew-managed on macOS, /usr/include on Linux.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	PROTOC_INCLUDE := $(shell brew --prefix protobuf)/include
else
	PROTOC_INCLUDE ?= /usr/include
endif

.PHONY: generate build test lint docker clean

generate:
	PATH="$(GOPATH)/bin:$(PATH)" protoc \
		--proto_path=pdp/proto \
		--proto_path=$(PROTOC_INCLUDE) \
		--go_out=pdp/gen/pdp \
		--go_opt=paths=source_relative \
		pdp/proto/model.proto

build: $(BINARY)

$(BINARY):
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -o $(BINARY) ./cmd/pdp-server

test:
	go test ./...

lint:
	go vet ./...

docker: $(BINARY)
	docker build --build-arg BASE_IMAGE=$(BASE_IMAGE) -t $(IMAGE) .

docker-push: docker
	./.local/docker-push.sh $(IMAGE)

clean:
	rm -rf bin
