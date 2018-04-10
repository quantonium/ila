include ../../config.mk

CFLAGS += -fPIC

UTILOBJ = dbif_redis.o daemonize.o

TARGETS= libqutil.a

all: $(TARGETS)

libqutil.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(ILIBDIR)


clean:
	@rm -f $(UTILOBJ) $(ADDLIB) $(TARGETS)
