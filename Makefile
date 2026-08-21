GO       ?= go
LINT     ?= golangci-lint
PACKAGES := $(shell $(GO) list ./... 2>/dev/null)

.PHONY: lint test

lint:
ifeq ($(PACKAGES),)
	@echo "no Go packages yet; lint skipped"
else
	$(GO) vet ./...
	$(LINT) run
	@test "$$(gofmt -l .)" = ""
endif

test:
ifeq ($(PACKAGES),)
	@echo "no Go packages yet; tests skipped"
else
	$(GO) test ./...
endif
