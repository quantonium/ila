OBJ=tcp_ping.o

include ../../config.mk

TARGETS=tcp_ping tcp_ping_server

all: $(TARGETS)

LDFLAGS +=

CFLAGS += -g

tcp_ping: $(OBJ) $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -liputil -lcurl -lfast -lcurl -lqutil $(LDLIBS) -o $@

tcp_ping_server: tcp_ping_server.o $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -lqutil -levent $(LDLIBS) -o $@

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(BINDIR)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 tcp_ping_server $(INSTALLDIR)$(BINDIR)

clean:
	@rm -f $(OBJ) $(TARGETS)
