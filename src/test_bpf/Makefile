LLC ?= llc
CLANG ?= clang

INCLUDE_PATHS := /usr/local/include /usr/local/include /usr/include

COMMON_FLAGS := $(foreach dir,$(INCLUDE_PATHS),-I$(TRACE_INSTALL_DIR)/$(dir))
LD_FLAGS = -L$(TRACE_INSTALL_DIR)/usr/lib64

%_kern.o: %_kern.c
	$(CLANG) $(NOSTDINC_FLAGS) $(COMMON_FLAGS) \
	$(EXTRA_CFLAGS) -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@


test_load.exe: test_kern.o test_load.c
	$(CC) -g -O0 $(COMMON_FLAGS) test_load.c -lbpf -lelf -o $@ $(LD_FLAGS)

clean:
	rm -rf *.o
	rm -f *.exe
