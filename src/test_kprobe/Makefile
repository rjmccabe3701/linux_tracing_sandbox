LLC ?= llc
CLANG ?= clang
CXX ?= g++
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
INCLUDE_PATHS := /usr/include
# INCLUDE_PATHS := /usr/local/include /usr/include
# INCLUDE_PATHS += /usr/include/bcc/compat

STAGING_DIR ?= $(TRACE_INSTALL_DIR)

COMMON_FLAGS := $(foreach dir,$(INCLUDE_PATHS),-I$(STAGING_DIR)/$(dir))
# LD_FLAGS = -L$(STAGING_DIR)/usr/lib64 -L$(STAGING_DIR)/usr/lib
LD_FLAGS = -L$(STAGING_DIR)/usr/lib64

all: MK_BUILD_DIR build/load_kprobe.exe

CLANG_ARCH_ARGS = -target x86_64
SRCARCH = X86_64

build/%_kern.o: %_kern.c MK_BUILD_DIR
	$(CLANG) $(NOSTDINC_FLAGS) $(COMMON_FLAGS) \
	$(EXTRA_CFLAGS)  \
		-D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(SRCARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@


build/load_kprobe.exe: build/kprobe_kern.o load_kprobe.c
	$(CC) -g -O0 $(COMMON_FLAGS) load_kprobe.c -lbpf -lelf \
		-o $@ $(LD_FLAGS)

.PHONY: MK_BUILD_DIR

MK_BUILD_DIR:
	mkdir -p $(ROOT_DIR)/build

clean:
	rm -rf $(ROOT_DIR)/build
