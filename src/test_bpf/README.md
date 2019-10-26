# Background info

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
[bpf_helpers.h](https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h).  **I will be using libbpf in
these examples**.


# Running the example:

To build just run ``make`` in this directory.  Then run ``test_load.exe``.  After doing this you should see:


```bash
% bpftool prog show
...
283: socket_filter  name socket_filter  tag dc6df1600f7067b5  gpl
        loaded_at 2019-10-21T12:02:36-0500  uid 0
        xlated 296B  jited 175B  memlock 4096B  map_ids 259
% bpftool map show
...
259: array  name my_map  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 4096B

```

Both the program and map have been pinned:

```bash
% ls /sys/fs/bpf/my_test/
bwMonitorMap  dummy_socket_filter  tailcallMap
```

The ``bwMonitorMap`` is pinned so that external programs can monitor the traffic flowing
through the interface.  For example:


```bash
% bpftool map dump id 655
key: 00 00 00 00  value: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
key: 01 00 00 00  value: 66 00 00 00 00 00 00 00  bc 25 00 00 00 00 00 00
key: 02 00 00 00  value: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
Found 3 elements
```

Or with [this](swig) python application

```python
>>> import TableReader
>>> t = TableReader.TableReader()
>>> V = t.getTable()
>>> print(V[1].pkts)
102
```

The ``tailcallMap`` allows adding tailcalls dynamically.

Note this at the bottom of the [socket_filter](test_kern.c) method:

```c
   bpf_tail_call(skb, &tailcallMap, 0);
   bpf_printk("No tailcall registered!\n");
```

If no tailcalls have been registered, the ``No tailcall registered!`` line will hit.

By running the ``add_tailcall.exe`` utility you will see (from cat-ting ``/sys/kernel/tracing/trace_pipe``) [this](tailcall_kern.c) method is now called.

This simple example doesn't illustrate the power of this technique; I imaging it's very useful if you want to attach dynamic eBPF programs to a qdisc filter:

```
tc filter ... bpf <TrampolineBpfMethod> ...
```

If this ``TrampolineBpfMethod`` has a tailcall hooks then you could modify this filtering behavior *without* having to do touch the qdisc settings.
