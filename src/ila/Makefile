TOPTARGETS := all clean install

SUBDIRS = ilad ilactld ilac ilactl redis amc

$(TOPTARGETS) : $(SUBDIRS)

$(SUBDIRS):
	@make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)

