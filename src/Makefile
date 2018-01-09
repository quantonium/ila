# Top level Makefile for NEOS source

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory -s
MFLAGS += -s
endif

ifneq ($(V), 1)
MFLAGS += -s
endif

PREFIX?=/usr
LIBDIR?=$(PREFIX)/lib
SBINDIR?=/sbin
BINDIR?=/bin
ETCDIR?=/etc
ILIBDIR?=/lib
CONFDIR?=/etc/idloc
DATADIR?=$(PREFIX)/share
HDRDIR?=$(PREFIX)/include/idloc
MANDIR?=$(DATADIR)/man
KERNEL_INCLUDE?=/usr/include
BASH_COMPDIR?=$(DATADIR)/bash-completion/completions
INSTALLDIR?=/usr

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRDIR := $(dir $(MKFILE_PATH))

SHARED_LIBS = y

DEFINES= -DLIBDIR=\"$(LIBDIR)\"
ifneq ($(SHARED_LIBS),y)
DEFINES+= -DNO_SHARED_LIBS
endif

DEFINES+=-DCONFDIR=\"$(CONFDIR)\"

CC := gcc
INSTALL := install
HOSTCC ?= $(CC)
DEFINES += -D_GNU_SOURCE
# Turn on transparent support for LFS
DEFINES += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CCOPTS = -O2
WFLAGS := -Wall -Wstrict-prototypes  -Wmissing-prototypes
WFLAGS += -Wmissing-declarations -Wold-style-definition -Wformat=2
CFLAGS += -fPIC -g

CFLAGS := $(WFLAGS) $(CCOPTS) -I$(CURRDIR)/include $(DEFINES) $(CFLAGS)
YACCFLAGS = -d -t -v
LDFLAGS += -L$(CURRDIR)/lib/iputil -L$(CURRDIR)/lib/qutil

SUBDIRS=lib ila

#LIBNETLINK=../lib/libnetlink.a ../lib/libutil.a ../lib/libdbifredis.a

#LDLIBS += $(LIBNETLINK)

all: config.mk
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) $(MFLAGS) -C $$i; done

config.mk:
	sh configure $(KERNEL_INCLUDE)

install: all
	@install -m 0755 -d $(INSTALLDIR)$(SBINDIR)
	@install -m 0755 -d $(INSTALLDIR)$(BINDIR)
	@install -m 0755 -d $(INSTALLDIR)$(ILIBDIR)
	@install -m 0755 -d $(INSTALLDIR)$(ETCDIR)
	@for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) $(MFLAGS) -C $$i install; done

snapshot:
	echo "static const char SNAPSHOT[] = \""`date +%y%m%d`"\";" \
		> include/SNAPSHOT.h

clean:
	@for i in $(SUBDIRS) ;\
	do $(MAKE) $(MFLAGS) -C $$i clean; done

clobber:
	touch config.mk
	$(MAKE) $(MFLAGS) clean
	rm -f config.mk cscope.*

distclean: clobber

cscope:
	cscope -b -q -R -Iinclude -sip -slib -smisc -snetem -stc

.EXPORT_ALL_VARIABLES:
