include ../../config.mk

TARGETS= ilactl.py

BIN= ilactl

all:

install_lib:
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $(TARGETS) $(INSTALLDIR)$(ILIBDIR)

install_bin:
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $(BIN) $(INSTALLDIR)$(BINDIR)

install: install_lib install_bin

clean:

