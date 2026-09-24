.PHONY: all fmt fmt-check vet test test-race test-e2e schema-check check build codex-interactive

PROJECT_PACKAGES := ./cmd/... ./internal/... ./pkg/...

all: check

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*' -not -path './dist/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*' -not -path './dist/*'))" || \
		{ echo 'Go files need formatting; run make fmt' >&2; exit 1; }

vet:
	go vet $(PROJECT_PACKAGES)

test:
	go test $(PROJECT_PACKAGES)

test-race:
	go test -race $(PROJECT_PACKAGES)

test-e2e:
	mkdir -p dist/e2e
	go build -o dist/e2e/benchmark ./cmd/benchmark
	go build -o dist/e2e/controlplane ./cmd/controlplane
	HTB_E2E=1 go test -race -count=1 ./internal/controlplane -run '^TestPhase1'

schema-check:
	python3 scripts/schema_check.py

check: fmt-check vet test-race schema-check

build:
	go build $(PROJECT_PACKAGES)

codex-interactive:
	limactl shell gvisor-dev -- bash $(CURDIR)/deploy/gvisor/scripts/codex-interactive.sh
