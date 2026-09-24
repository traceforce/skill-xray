.PHONY: all build install-opengrep test lint vuln sec ci fuzz clean help

GO ?= go
FUZZTIME ?= 30s
ifeq ($(OS),Windows_NT)
EXE := .exe
endif
BINARY = bin/skill-xray$(EXE)

all: build ## Build the binary (default)

build: ## Build the skill-xray binary into bin/
	$(GO) build -o bin/ ./cmd/skill-xray

install-opengrep: build ## Download and verify the pinned OpenGrep runtime through the built binary
	$(BINARY) install-opengrep

test: ## Run every test package
	$(GO) test -timeout 30m ./...

lint: ## Run go vet and staticcheck
	$(GO) vet ./...
	GOTOOLCHAIN=go1.26.6 $(GO) run honnef.co/go/tools/cmd/staticcheck@2025.1 ./...

vuln: ## Check every dependency against the Go vulnerability database
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

sec: ## Run gosec over the product code at medium severity and confidence
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -quiet -severity medium -confidence medium -exclude-dir internal/testutil -exclude-dir tools ./...

ci: ## Run the same checks CI runs: build, vet, test
	$(GO) build ./...
	$(GO) vet ./...
	$(GO) test -timeout 30m ./...

fuzz: ## Run every fuzz target for FUZZTIME each; a crasher lands in <pkg>/testdata/fuzz/
	@for f in internal/*/*_fuzz_test.go; do for fn in $$(grep -oE '^func Fuzz\w+' $$f | cut -c6-); do \
	  echo "== $$f $$fn"; $(GO) test -run='^$$' -fuzz="^$$fn\$$" -fuzztime=$(FUZZTIME) ./$$(dirname $$f) || exit 1; done; done

clean: ## Remove bin/
	rm -rf bin

help: ## Show this help message
	@echo "Available targets:"
	@awk -F ':.*## ' '/^[a-zA-Z_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
