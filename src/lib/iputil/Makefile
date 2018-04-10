include ../../config.mk

CFLAGS += -fPIC

UTILOBJ = utils.o rt_names.o ll_types.o ll_proto.o ll_addr.o \
	inet_proto.o namespace.o json_writer.o json_print.o \
	names.o color.o bpf.o exec.o fs.o

NLOBJ=libgenl.o ll_map.o libnetlink.o

TARGETS= libnetlink.a libiputil.a

all: $(TARGETS)

libnetlink.a: $(NLOBJ)
	$(QUIET_AR)$(AR) rcs $@ $^

libiputil.a: $(UTILOBJ) $(ADDLIB)
	$(QUIET_AR)$(AR) rcs $@ $^

install: $(TARGETS)
	$(QUIET_INSTALL)$(INSTALL) -m 0755 $^ $(INSTALLDIR)$(ILIBDIR)

clean:
	@rm -f $(NLOBJ) $(UTILOBJ) $(ADDLIB) $(TARGETS)
