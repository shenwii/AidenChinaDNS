CC ?= cc
PREFIX ?= /usr/local

SRCDIR = src
OBJDIR = obj
BINDIR = bin
PREFIX_BIN = $(PREFIX)/$(BINDIR)

BIN = $(BINDIR)/ac-dns

CFLAGS += -Wall
LDFLAGS += -liniparser -lsqlite3

ifeq ($(OS),Windows_NT)
CFLAGS += -D_WIN32_WINNT=0x0600
LDFLAGS += -lws2_32 -lIphlpapi
endif

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG -g -O0
else
LDFLAGS += -s -Os
endif

SOURCES = ascore.c common.c iconf.c dns.c cidr.c dnsprot.c
OBJECTS = $(patsubst %.c,$(OBJDIR)/%.o,$(SOURCES))

all: $(BIN)

$(BIN): $(OBJDIR) $(BINDIR) $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

$(BINDIR):
	@mkdir -p $(BINDIR)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(PREFIX_BIN):
	@mkdir -p $(PREFIX_BIN)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	@rm -rf $(OBJDIR) $(BINDIR)

install: all $(PREFIX_BIN)
	cp -fp $(BIN) $(PREFIX_BIN)

uninstall:
	rm -rf $(PREFIX)/$(BIN)

.PHONY: all clean install uninstall
