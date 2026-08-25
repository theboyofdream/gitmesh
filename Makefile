CC      ?= cc
CFLAGS  := -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE
LDLIBS  := -lsodium -llz4

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Darwin)
  PLATFORM := darwin
else ifeq ($(OS),Windows_NT)
  PLATFORM := win32
  LDLIBS := -lws2_32 -lsodium -llz4
else
  PLATFORM := linux
endif
CFLAGS += -Isrc/platform -Isrc/platforms/$(PLATFORM)

SRC := src/util.c src/ident.c src/disco.c src/index.c src/proto.c src/sync.c src/main.c

gitmesh: $(SRC) src/gitmesh.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

test: gitmesh
	sh tests/run.sh

clean:
	rm -f gitmesh

.PHONY: test clean
