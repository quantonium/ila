OBJ=ilactld_main.o

include ../../config.mk

TARGETS=ilactld

all: $(TARGETS)

LDFLAGS += -liputil -lqutil -lhiredis -lnetlink -lmnl

CFLAGS += -g

ilactld: $(OBJ) $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -levent $(LDLIBS) -o $@

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(BINDIR)

clean:
	@rm -f $(OBJ) $(TARGETS)
