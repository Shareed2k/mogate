GO ?= go
CC ?= cc
BIN_DIR ?= bin

ifeq ($(shell $(GO) env GOOS),darwin)
LIBRARY := $(BIN_DIR)/libmogate.dylib
SHARED_FLAGS := -dynamiclib -Wno-deprecated-declarations
else
LIBRARY := $(BIN_DIR)/libmogate.so
SHARED_FLAGS := -shared
endif

.PHONY: all generate build test test-injector-c e2e clean

all: build

# generate refreshes the code-generated protocol artifacts, including the
# gitignored injector/protocol_generated.h header that the injector build below
# includes. build depends on it so a fresh clone builds without a manual step.
generate:
	$(GO) generate ./...

build: generate
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/mogate ./cmd/mogate
	sed -n '/^\/\*$$/,/^\*\/$$/p' injector/main.go | sed '1d;$$d;/^#cgo /d' | \
		$(CC) -x c -Iinjector -O2 -fPIC $(SHARED_FLAGS) -ldl -pthread -o $(LIBRARY) -

test: test-injector-c
	$(GO) test -race ./...

# test-injector-c runs the darwin-only injector SIP cgo parity tests
# (TestCSip*), which exercise the C copy/thin/ad-hoc-resign patcher against the
# Go golden vectors. SIP patching is a macOS concern, so this is a clean no-op
# on linux.
ifeq ($(shell $(GO) env GOOS),darwin)
# The cgo tests include the gitignored injector/protocol_generated.h header, so
# generate first to make sure it is present.
test-injector-c: generate
	cd injector && $(GO) test -run TestCSip ./...
else
test-injector-c:
	@echo "test-injector-c: skipped (SIP patching is darwin-only)"
endif

e2e:
	cd test/e2e && $(GO) test -tags=integration -v -timeout=15m ./...

clean:
	rm -rf $(BIN_DIR)
