BINARY    := corvus
CMD       := ./cmd/corvus
BUILD_DIR := ./bin
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: all build clean test lint install uninstall

all: build

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)

install: build
	install -m 0755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)

uninstall:
	rm -f /usr/local/bin/$(BINARY)

test:
	go test ./... -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	go mod tidy

fmt:
	gofmt -w .

run: build
	$(BUILD_DIR)/$(BINARY) $(ARGS)
