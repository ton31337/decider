GOMINVERSION = 1.16
GO111MODULE = on
export GO111MODULE

GOVERSION := $(shell go version | awk '{print substr($$3, 3)}')
GOISMIN := $(shell expr "$(GOVERSION)" ">=" "$(GOMINVERSION)")
ifneq "$(GOISMIN)" "1"
$(error "go version $(GOVERSION) is not supported, upgrade to $(GOMINVERSION) or above")
endif

check:
	go fmt ./...
	go fix ./...
	go vet -v ./...
	staticcheck ./... || true
	go mod tidy
	golines -w ./
	golangci-lint run

linux-client:
	@-go build -o decider
clean:
	rm -f ./decider

.DEFAULT_GOAL := linux-client
