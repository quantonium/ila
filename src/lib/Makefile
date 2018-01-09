include ../config.mk

TOPTARGETS := all clean install

SUBDIRS = iputil qutil qmodules

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

