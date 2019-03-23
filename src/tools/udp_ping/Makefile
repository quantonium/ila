OBJ=udp_ping.o

include ../../config.mk

TARGETS=udp_ping udp_ping_server

all: $(TARGETS)

LDFLAGS +=

CFLAGS += -g

udp_ping: $(OBJ) $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -liputil -lcurl -lfast -lcurl -lqutil $(LDLIBS) -o $@

udp_ping_server: udp_ping_server.o $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) -lqutil -levent $(LDLIBS) -o $@

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(BINDIR)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 udp_ping_server $(INSTALLDIR)$(BINDIR)

clean:
	@rm -f $(OBJ) $(TARGETS)
