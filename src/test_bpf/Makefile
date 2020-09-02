LLC ?= llc
CLANG ?= clang
CXX ?= g++
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
INCLUDE_PATHS := usr/include/bpf/compat
INCLUDE_PATHS += usr/include

COMMON_LIBS:= bpf elf z
STAGING_DIR ?= $(TRACE_INSTALL_DIR)

COMMON_FLAGS := $(foreach dir,$(INCLUDE_PATHS),-I$(STAGING_DIR)/$(dir))
COMMON_LIBS := $(foreach lib,$(COMMON_LIBS),-l$(lib))

# LD_FLAGS = -L$(STAGING_DIR)/usr/lib64 -L$(STAGING_DIR)/usr/lib
LD_FLAGS = -L$(STAGING_DIR)/usr/lib64

all: MK_BUILD_DIR build/test_load.exe build/add_tailcall.exe build/_TableReader.so

build/%_kern.o: %_kern.c
	$(CLANG) $(NOSTDINC_FLAGS) $(COMMON_FLAGS) \
	$(EXTRA_CFLAGS) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@


build/test_load.exe: build/test_kern.o test_load.cpp
	$(CXX) -std=c++17 -g -O0 $(COMMON_FLAGS) test_load.cpp $(COMMON_LIBS) \
		-o $@ $(LD_FLAGS)

build/add_tailcall.exe: build/tailcall_kern.o add_tailcall.cpp
	$(CXX) -std=c++17 -g -O0 $(COMMON_FLAGS) add_tailcall.cpp $(COMMON_LIBS) \
		-o $@ $(LD_FLAGS)

build/TableReader.o: swig/TableReader.cpp
	$(CXX) -std=c++17 -fPIC -g -O0 -c $(COMMON_FLAGS) swig/TableReader.cpp -o $@

build/_TableReader.so: build/TableReader.o swig/TableReader.i
	swig -c++ -python -o build/TableReader_wrap.cxx swig/TableReader.i && \
	$(CXX) $(COMMON_FLAGS) -c -std=c++17 -I/usr/include/python3.6 -I$(ROOT_DIR)/swig -fPIC -g \
			-O0 build/TableReader_wrap.cxx -o build/TableReader_wrap.o && \
	$(CXX) -Xlinker -export-dynamic $(COMMON_FLAGS) -std=c++17 -shared -fPIC -g -O0 build/TableReader.o build/TableReader_wrap.o \
			-lpython3.6m $(COMMON_LIBS) -lbcc -o build/_TableReader.so

.PHONY: MK_BUILD_DIR

MK_BUILD_DIR:
	mkdir -p $(ROOT_DIR)/build

clean:
	rm -rf $(ROOT_DIR)/build
