include ../../config.mk

CFLAGS += -fPIC

UTILOBJ = fast_client.o

TARGETS= libfast.so

all: $(TARGETS)

LDFLAGS += -lcurl

libfast.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

libfast.so: $(UTILOBJ) $(ADDLIB)
	$(CC) -shared fast_client.o -o libfast.so

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $< $(INSTALLDIR)$(ILIBDIR)

clean:
	@rm -f $(UTILOBJ) $(ADDLIB) $(TARGETS)
