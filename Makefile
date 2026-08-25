CC      ?= cc
BREW    := $(shell command -v brew >/dev/null 2>&1 && brew --prefix)
ifneq ($(BREW),)
  CFLAGS  += -I$(BREW)/include
  LDFLAGS += -L$(BREW)/lib
endif
CFLAGS  := -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE $(CFLAGS)
LDLIBS  := $(LDFLAGS) -lsodium -llz4

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Darwin)
  PLATFORM := darwin
else ifeq ($(OS),Windows_NT)
  PLATFORM := win32
  LDLIBS := -lws2_32 -lsodium -llz4
else
  PLATFORM := linux
endif
CFLAGS += -Isrc/common -Isrc -Isrc/platforms/$(PLATFORM)

SRC := src/util.c src/identity.c src/discovery.c src/index.c src/proto.c src/sync.c src/main.c

gitmesh: $(SRC) src/common/gitmesh.h src/platform.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

test: gitmesh
	sh tests/run.sh

compile_commands.json: Makefile
	@rm -f $@
	@printf '[\n' >> $@
	@sep=
	@for f in $(SRC); do \
	  printf '%s  {"directory": "%s", "command": "%s %s -c \\"%s/%s\\"", "file": "%s"}\n' \
	    "$$sep" "$$(pwd)" "$(CC)" "$(CFLAGS)" "$$(pwd)" "$$f" "$$f" >> $@; \
	  sep=,; \
	done
	@printf ']\n' >> $@

clean:
	rm -f gitmesh

.PHONY: test clean compile_commands.json
