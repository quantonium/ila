include ../../config.mk

TARGETS= redis_6379.conf redis_6380.conf redis_6381.conf

all:

install: $(TARGETS)
	 $(QUIET_INSTALL)$(INSTALL) -m 0755 $(TARGETS) $(INSTALLDIR)$(ETCDIR)

clean:


