BINARY_NAME=mcp-sct
VERSION=0.5.0
BUILD_DIR=bin
GO=go

.PHONY: all build test clean install docker cloud

all: build

build:
	CGO_ENABLED=1 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) -ldflags "-s -w -X main.version=$(VERSION)" ./cmd/mcp-sct/

test:
	CGO_ENABLED=1 $(GO) test -v -count=1 ./...

test-short:
	CGO_ENABLED=1 $(GO) test -count=1 ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

lint:
	$(GO) vet ./...

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

cloud: build
	$(BUILD_DIR)/$(BINARY_NAME) --mode cloud --addr :8080

docker:
	docker build -t mcpsct/mcp-sct:$(VERSION) -f deployments/docker/Dockerfile .
	docker tag mcpsct/mcp-sct:$(VERSION) mcpsct/mcp-sct:latest

docker-push: docker
	docker push mcpsct/mcp-sct:$(VERSION)
	docker push mcpsct/mcp-sct:latest

# Deploy no Docker Swarm
swarm-deploy:
	docker stack deploy -c deployments/docker/stack-mcp-sct.yml mcp_sct

swarm-remove:
	docker stack rm mcp_sct

# Dev local com docker-compose
dev-docker:
	docker-compose -f deployments/docker/docker-compose.yml up --build
