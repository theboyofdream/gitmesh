CC      ?= cc
CFLAGS  := -std=c11 -O2 -Wall -Wextra -D_GNU_SOURCE
LDLIBS  := -lsodium -llz4

SRC := src/util.c src/ident.c src/disco.c src/index.c src/proto.c src/sync.c src/main.c

gitmesh: $(SRC) src/gitmesh.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

test: gitmesh
	sh tests/run.sh

clean:
	rm -f gitmesh

.PHONY: test clean
