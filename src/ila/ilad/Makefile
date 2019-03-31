OBJ=ilad_main.o ila_kernel.o ilad_amfp.o

include ../../config.mk

TARGETS=ilad

all: $(TARGETS)

LDFLAGS += -liputil -lqutil -lhiredis -lnetlink -lmnl

CFLAGS += -g

ilad: $(OBJ) $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -levent $(LDLIBS) -o $@

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(BINDIR)

clean:
	@rm -f $(OBJ) $(TARGETS)
