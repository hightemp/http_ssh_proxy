BINARY_NAME=http_ssh_proxy
GO=go
GOBUILD=$(GO) build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v