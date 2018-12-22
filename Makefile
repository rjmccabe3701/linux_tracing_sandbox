SHELL = bash
.ONESHELL:
DESTDIR=$(shell pwd)/install
LINUXTOOLS=$(shell pwd)/linux/tools

all: perf bpftools iproute2 set_env


perf:
	make -j -C $(LINUXTOOLS)/perf DESTDIR=$(DESTDIR) install install-man

bpftools:
	make -j -C $(LINUXTOOLS)/bpf DESTDIR=$(DESTDIR) install bpftool_install

iproute2:
	$(PWD)/iproute2/configure
	make -j  -C $(PWD)/iproute2 DESTDIR=$(DESTDIR) install

set_env: FORCE
	cat <<- EOF > $@
		export MANPATH=$(DESTDIR)/usr/share/man:$$MANPATH
		export PATH=$(DESTDIR)/sbin:$(DESTDIR)/bin:$(DESTDIR)/usr/local/bin:$(DESTDIR)/usr/local/sbin:$$PATH
		export LD_LIBRARY_PATH=$(DESTDIR)/lib64
		export PERF_EXEC_PATH=$(DESTDIR)/libexec/perf-core
	EOF

clean:
	rm -rf set_env
	rm -rf $(PWD)/install
	make -C $(LINUXTOOLS)/perf clean
	make -C $(LINUXTOOLS)/bpf clean
	make -C $(PWD)/iproute2 clean

.PHONY: all perf bpftools iproute2 FORCE
