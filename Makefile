CC ?= cc
CFLAGS ?= -O2 -std=c99
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

all: nettop

nettop: nettop.c
	$(CC) $(CFLAGS) -o nettop nettop.c

install: nettop
	mkdir -p $(BINDIR)
	cp nettop $(BINDIR)/nettop
	chmod 755 $(BINDIR)/nettop

clean:
	rm -f nettop

.PHONY: all install clean
