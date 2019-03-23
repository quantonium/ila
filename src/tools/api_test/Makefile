OBJ=api_test.o

include ../../config.mk

TARGETS=api_test

all: $(TARGETS)

LDFLAGS +=

CFLAGS += -g

api_test: $(OBJ) $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -liputil -lqutil -lnetlink $(LDLIBS) -o $@

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(BINDIR)

clean:
	@rm -f $(OBJ) $(TARGETS)
