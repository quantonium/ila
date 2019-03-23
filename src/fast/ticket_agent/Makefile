include ../../config.mk

TARGETS= fast_server.py

BIN= fast_server

all:

install_lib:
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $(TARGETS) $(INSTALLDIR)$(ILIBDIR)

install_bin:
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $(BIN) $(INSTALLDIR)$(SBINDIR)

install: install_lib install_bin

clean:

