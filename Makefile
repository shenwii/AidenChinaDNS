CC ?= cc
PREFIX ?= /usr/local

SRCDIR = src
OBJDIR = obj
BINDIR = bin
PREFIX_BIN = $(PREFIX)/$(BINDIR)

BIN = $(BINDIR)/ac-dns

CFLAGS += -Os -Wall
LDFLAGS += -liniparser -lpthread -lsqlite3

ifdef DEBUG
CFLAGS += -DDEBUG -g
else
LDFLAGS += -s
endif

SOURCES = ascore.c common.c iconf.c thrdpool.c dns.c cidr.c
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
