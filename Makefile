GO ?= go
LDFLAGS ?= -w -s
OUTPUT ?= cadrega

.PHONY: build test clean

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(OUTPUT) cmd/cadrega/main.go

test:
	$(GO) test ./...

clean:
	$(GO) clean
	rm -f $(OUTPUT)
