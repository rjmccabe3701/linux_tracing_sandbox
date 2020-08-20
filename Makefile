SHELL = bash
.ONESHELL:
DESTDIR=$(shell pwd)/install
LINUXTOOLS=$(shell pwd)/linux/tools
TOOLS=$(shell pwd)/tools

TARGETS:=bpftools iproute2 \
	kernel_bpf_samples libbpf \
	set_env

# TARGETS+=perf

OPTIONAL_TARGETS:=iptables \
	nftables \
	libnftnl

define ADD_TARGET
ifneq ($(wildcard $(TOOLS)/$(1)),)
	$(info "here with $(TOOLS)/$(1)")
	TARGETS:=$(TARGETS) $(1)
endif
endef

$(foreach prog,$(OPTIONAL_TARGETS),$(eval $(call ADD_TARGET,$(prog))))


# EXTRA_CFLAGS='-O0 -g -Wall'
# EXTRA_CFLAGS=''

all: $(TARGETS)

check_targets:
	@echo "targets = $(TARGETS)"

perf:
	make -j -C $(LINUXTOOLS)/perf DESTDIR=$(DESTDIR) install install-man

bpftools:
	make -j -C $(LINUXTOOLS)/bpf QUIET_CC= EXTRA_CFLAGS=$(EXTRA_CFLAGS) DESTDIR=$(DESTDIR) install bpftool_install

libbpf:
	make -j -C $(TOOLS)/libbpf/src BUILD_STATIC_ONLY=y DESTDIR=$(DESTDIR) install

iproute2:
	$(TOOLS)/iproute2/configure
	make -j  -C $(TOOLS)/iproute2 DESTDIR=$(DESTDIR) install

iptables: libnftnl
	cd $(TOOLS)/iptables; ./autogen.sh; \
		PKG_CONFIG_PATH=$(DESTDIR)/lib/pkgconfig ./configure --with-kernel=$(PWD)/linux --prefix $(DESTDIR); \
		make -j && make install

nftables: libnftnl
	cd $(TOOLS)/nftables; ./autogen.sh; \
		PKG_CONFIG_PATH=$(DESTDIR)/lib/pkgconfig ./configure --prefix $(DESTDIR); \
		make -j && make install

libnftnl:
	cd $(TOOLS)/libnftnl; ./autogen.sh; \
		./configure --prefix $(DESTDIR); \
		make -j && make install

kernel_bpf_samples: linux_headers_install
	make LLC=/usr/bin/llc-10 -C $(PWD)/linux samples/bpf/

linux_headers_install:
	make -C $(PWD)/linux INSTALL_HDR_PATH=$(DESTDIR)/usr headers_install

set_env: FORCE
	cat <<- EOF > $@
		export MANPATH=$(DESTDIR)/usr/share/man:$$MANPATH
		export PATH=$(DESTDIR)/sbin:$(DESTDIR)/bin:$(DESTDIR)/usr/local/bin:$(DESTDIR)/usr/local/sbin:$$PATH
		export TRACE_INSTALL_DIR=$(DESTDIR)
		export LD_LIBRARY_PATH=$(DESTDIR)/usr/local/lib64:$(DESTDIR)/lib
		export PERF_EXEC_PATH=$(DESTDIR)/libexec/perf-core:
		export PYTHONPATH=$(DESTDIR)/lib/python3/dist-packages
	EOF

clean:
	rm -rf set_env; \
	rm -rf $(PWD)/install; \
	make -C $(LINUXTOOLS)/perf clean; \
	make -C $(LINUXTOOLS)/bpf clean; \
	make -C $(PWD)/linux/samples/bpf clean; \
	make -C $(TOOLS)/libbpf/src clean; \
	make -C $(TOOLS)/iproute2 clean; \
	if [ -d $(TOOLS)/iptables ]; then \
		make -C $(TOOLS)/iptables distclean; \
	fi; \
	if [ -d $(TOOLS)/nftables ]; then \
		make -C $(TOOLS)/nftables distclean; \
	fi; \
	if [ -d $(TOOLS)/libnftnl ]; then \
		make -C $(TOOLS)/libnftnl distclean; \
	fi

.PHONY: $(TARGETS) FORCE
