.PHONY: all build install-opengrep test lint vuln ci parity corpus fuzz clean help

GO ?= go
PYTHON ?= python
ORACLE ?= .
MSB ?= ../_reference/msb-snapshot
J ?= 4
FUZZTIME ?= 30s
ifeq ($(OS),Windows_NT)
PATHSEP := ;
EXE := .exe
else
PATHSEP := :
endif
BINARY = bin/skill-xray$(EXE)

all: build ## Build the binary (default)

build: ## Build the skill-xray binary into bin/
	$(GO) build -o bin/ ./cmd/skill-xray

install-opengrep: build ## Download and verify the pinned OpenGrep runtime through the built binary
	$(BINARY) install-opengrep

test: ## Run every test package; the parity gates skip themselves when corpus/ is absent
	$(GO) test -timeout 30m ./...

lint: ## Run go vet and staticcheck
	$(GO) vet ./...
	GOTOOLCHAIN=go1.26.6 $(GO) run honnef.co/go/tools/cmd/staticcheck@2025.1 ./...

vuln: ## Check every dependency against the Go vulnerability database
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

ci: ## Run the same checks CI runs: build, vet, test
	$(GO) build ./...
	$(GO) vet ./...
	$(GO) test -timeout 30m ./...

parity: build ## Compare the Go scanner with the Python oracle over the fixtures under corpus/
	@[ -f corpus/pytest/manifest.jsonl ] || $(MAKE) corpus
	$(GO) run ./tools/parity run --corpus corpus/pytest --corpus corpus/msb-test -j $(J)

corpus: ## Materialise the parity fixtures under corpus/ from the oracle's test suite
	PYTHONPATH="tools/parity$(PATHSEP)$(ORACLE)/src" $(PYTHON) -m pytest $(ORACLE)/tests -q -p pytest_dump_corpus --dump-corpus corpus/pytest
	@if [ -d "$(MSB)" ]; then $(PYTHON) tools/parity/msb_materialize.py --data $(MSB) --split test --out corpus/msb-test; \
	else echo "corpus: MSB snapshot $(MSB) absent, msb-test skipped"; fi

fuzz: ## Run every fuzz target for FUZZTIME each; a crasher lands in <pkg>/testdata/fuzz/
	@for f in internal/*/*_fuzz_test.go; do for fn in $$(grep -oE '^func Fuzz\w+' $$f | cut -c6-); do \
	  echo "== $$f $$fn"; $(GO) test -run='^$$' -fuzz="^$$fn\$$" -fuzztime=$(FUZZTIME) ./$$(dirname $$f) || exit 1; done; done

clean: ## Remove bin/
	rm -rf bin

help: ## Show this help message
	@echo "Available targets:"
	@awk -F ':.*## ' '/^[a-zA-Z_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
