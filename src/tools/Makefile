TOPTARGETS := all clean install

SUBDIRS = udp_ping tcp_ping api_test

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

