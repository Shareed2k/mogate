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

.PHONY: all build test e2e clean

all: build

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/mogate ./cmd/mogate
	sed -n '/^\/\*$$/,/^\*\/$$/p' injector/main.go | sed '1d;$$d;/^#cgo /d' | \
		$(CC) -x c -Iinjector -O2 -fPIC $(SHARED_FLAGS) -ldl -pthread -o $(LIBRARY) -

test:
	$(GO) test -race ./...

e2e:
	cd test/e2e && $(GO) test -tags=integration -v -timeout=15m ./...

clean:
	rm -rf $(BIN_DIR)
