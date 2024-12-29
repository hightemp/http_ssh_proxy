BINARY_NAME=http_ssh_proxy
GO=go
GOBUILD=$(GO) build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v

build-static:
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-w' -o $(BINARY_NAME)_static .