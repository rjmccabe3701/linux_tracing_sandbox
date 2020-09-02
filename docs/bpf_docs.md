# My BPF Documentation

This page is a result of my exploration of of eBPF (I'm still trying to get my head around it).

## BPF Background info

The kernel's [low-level bpf API](http://man7.org/linux/man-pages/man2/bpf.2.html) is essentially
a system call with flags to add eBPF programs/maps, etc. The programs are in the form of assembly
instructions (see [this](https://www.kernel.org/doc/Documentation/networking/filter.txt]) for the ISA).
The [kernel bpf examples](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/bpf?h=v5.3.7)
showcase a few ways of writing eBPF programs.

They use instruction-wrapping [macros](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/bpf/bpf_insn.h)
to hand code the programs.  For example [this](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/bpf/cookie_uid_helper_example.c?h=v5.3.7#n80).
For most users, writing this raw assembly isn't appealing so they also showcase how to write the programs in
c -- for example [this](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/bpf/map_perf_test_kern.c) -- then
use Clang to generate the instructions.

While the later approach is more attractive to mortals, this method has a few hurdles.

*  There are numerous eBPF c macros that the kernel examples utilize, for example ``SEC(.)`` to mark ELF
   sections, and several``bpf_`` helper functions.  These macros are only available in
   kernel-local locations, for example
   [bpf_helpers.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/testing/selftests/bpf/bpf_helpers.h).
   To make matters worse, it seems that other tools have their own collection of macros, for example
   [iproute2](https://github.com/shemminger/iproute2/blob/master/include/bpf_api.h).  It would be nice if
   these eBPF headers were standard (and available in package) so users can clang-compile eBPF programs
   outside the kernel (or iproute2).  The existence of this [bpf-helpers](https://manpages.debian.org/testing/manpages/bpf-helpers.7.en.html)
   makes me belive that this header will likely become the standard someday.  But until that point, should
   users resort to copying ``bpf_helpers.h`` (and friends) to their local repository?

*  There is a fair amount of [black-magic](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/bpf/bpf_load.c)
   in the kernel samples to actually load the eBPF programs.  The ``*_user.c`` programs will do something like
   ``load_bpf_file('/path/to/compiled/eBPF_prog.o``).  This method is responsible for parsing the ELF section,
   loading the program/maps into the kernel (the kernel returns a file descriptor to each) and much more.
   One particular aspect that is confusing is how a map's file descriptor is inserted into the clang-generated
   object file for a particular program.  For example:


```c
struct bpf_map_def SEC("maps") hash_map = {
   .type = BPF_MAP_TYPE_HASH,
   .key_size = sizeof(u32),
   .value_size = sizeof(long),
   .max_entries = MAX_ENTRIES,
};

SEC("kprobe/sys_getuid")
int stress_hmap(struct pt_regs *ctx)
{
   u32 key = bpf_get_current_pid_tgid();
   long init_val = 1;
   long *value;

   //How does this get translated to the required eBPF bytecode?
   //For example:
   // BPF_LD_MAP_FD(BPF_REG_1, map_fd),
   // BPF_MOV64_REG(BPF_REG_2, BPF_REG_7),
   // BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
   //          BPF_FUNC_map_lookup_elem),
   bpf_map_update_elem(&hash_map, &key, &init_val, BPF_ANY);
   value = bpf_map_lookup_elem(&hash_map, &key);
   if (value)
      bpf_map_delete_elem(&hash_map, &key);

   return 0;
}
```

   From what I can tell, the kernel-internal ``bpf_load`` library will re-write instructions after the
   bpf-map file descriptors are available, see [this](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/bpf/bpf_load.c?h=v5.3.7#n598).
   Iproute2 has its own internal [implementation](https://github.com/shemminger/iproute2/blob/v5.1.0/lib/bpf.c#L2396-L2397).
   While this is clever, its annoying this this code is just part of the kernel sample suite and not available to users.


It looks like other tools (for example, [bcc](https://github.com/iovisor/bcc/tree/master/src/cc)), have begun
standardizing on the [libbpf](https://github.com/libbpf/libbpf) library.  Also it seems that
[bpftool](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/tools/bpf/bpftool?h=v5.3.7)
is using libbpf under the hood.  See [playing_with_bpftool](playing_with_bpftool.md) for examples of what
bpftool can do.

**UPDATE**  The libbpf library is now exporting the
[bpf_helpers.h](https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h).



## Capturing kernel data via perf buffers

See ``samples/trace_output_{kern,user}.c``


```c
struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = 2,
};

SEC("kprobe/sys_write")
int bpf_prog1(struct pt_regs *ctx)
{
	struct S {
		u64 pid;
		u64 cookie;
	} data;

	data.pid = bpf_get_current_pid_tgid();
	data.cookie = 0x12345678;

	bpf_perf_event_output(ctx, &my_map, 0, &data, sizeof(data));

	return 0;
}
```

```c
static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct {
		__u64 pid;
		__u64 cookie;
	} *e = data;

	if (e->cookie != 0x12345678) {
		printf("BUG pid %llx cookie %llx sized %d\n",
		       e->pid, e->cookie, size);
		return;
	}

	cnt++;

	if (cnt == MAX_CNT) {
		printf("recv %lld events per sec\n",
		       MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
		return;
	}
}

int main(int argc, char **argv)
{
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;
	char filename[256];
	FILE *f;
	int ret;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	pb_opts.sample_cb = print_bpf_output;
	pb = perf_buffer__new(map_fd[0], 8, &pb_opts);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

	f = popen("taskset 1 dd if=/dev/zero of=/dev/null", "r");
	(void) f;

	start_time = time_get_ns();
	while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && cnt < MAX_CNT) {
	}
	kill(0, SIGINT);
	return ret;
}
```
----

## List of eBPF helper functions

See https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L3399

But each program type can access only a subset of those.  See ``bpftool feature``.

Note:

* ``bpf_probe_read`` and ``bpf_probe_read_kernel`` (same thing) are used to safely read kernel memory.
*  There is no ``bpf_probe_write_kernel`` (as that would compromise the system), but there is a ``bpf_probe_write_user``. The
   [test_probe_write example](https://github.com/torvalds/linux/blob/master/samples/bpf/test_probe_write_user_user.c) shows how
   an eBPF program can

---

## load_{byte,half,word} weirdness

In several kernel bpf network examples I see things like:

```c

int bpf_prog1(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
   //...
}

```

This confused me because ``load_byte`` is defined as

```c
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");

```

whatever that means.  At first glance this is loading memory from an offset of the ``__sk_buff`` struct, which is strange, because this struct is a read-only mirror of
the various attributes of the actual skbuff. I would think if a bpf program wants to load data from ``skb->data`` it would do:

```c
__u8 field;
bpf_probe_read(&field, 1, ((__u8*)skb->data) + ETH_HLEN + offsetof(struct iphdr, protocol));
```

Also there is a ``bpf_skb_load_bytes`` ... my god how confusing.

The paper [Advanced programmability and recent updates with tc’s cls bpf](https://netdevconf.info/1.2/papers/borkmann.pdf)


> LLVM supports the following built-ins for its eBPF back end,
> that is, llvm.bpf.load.byte, llvm.bpf.load.half and
> llvm.bpf.load.word. They map to BPF LD | BPD ABS
> and BPF LD | BPF IND equivalents for BPF B, BPF H and
> BPF W respectively, that have been carried over from cBPF mostly
> for legacy reasons in order to support efficient cBPF to eBPF migrations in the kernel,
> and as such they are the only skb-specific eBPF
> instructions. Based on the given offset, JITs can implement them
> quite efficiently, meaning, instructions are emitted that load from
> skb->data directly instead of emitting a function call

Note sure I understand completely, but it seems ``load_{byte,half,word}`` helpers are just used for accessing network packet data efficiently.

---


# Containers and bpf

Bpf programs/maps are global to the system (doing a ``bpf prog/map show`` shows any prog/map created in any container or on the raw host)
The ``/sys/fs/bpf`` mount isn't shared however, so pinning a map to ``/sys/fs/bpf`` in a container does not pin it to the host.

---

# Unsolved

* I find it annoying that you cannot access namespace information in eBPF programs.  For example if I am tracing packets in the Linux kernel, it would be nice to filter just on the namespace (container) of interest.  It looks like the Cilium team added the [``get_ns_cookie``](
https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git/commit/?id=f318903c0bf42448b4c884732df2bbb0ef7a2284) eBPF helper for just checking if they are in the root namespace or not.  I wish this was more extensible.