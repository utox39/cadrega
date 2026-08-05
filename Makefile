GO ?= go
LDFLAGS ?= -w -s
OUTPUT ?= cadrega

.PHONY: build test clean

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(OUTPUT) cmd/cadrega/main.go

test:
	$(GO) test ./... -v

clean:
	$(GO) clean
	rm -f $(OUTPUT)
