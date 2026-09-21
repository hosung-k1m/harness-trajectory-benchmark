.PHONY: all fmt fmt-check vet test test-race check build

all: check

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || \
		{ echo 'Go files need formatting; run make fmt' >&2; exit 1; }

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./...

check: fmt-check vet test-race

build:
	go build ./...

