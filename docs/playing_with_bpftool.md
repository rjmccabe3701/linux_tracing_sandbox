See https://www.mankier.com/8/bpftool-prog for some bpftool documentation.  It seems that bpftool isn't an
official package of any Linux distribution yet.  It does seem to use a fair bit of the libbpf library, so
until it becomes an official tool, I can pilfer its source to do what I want.


# Get running kernel's eBPF capabilities:

```bash
bpftool feature probe kernel
```

# Random examples

Let's try just loading our Clang-compiled snippet:

```c
#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("dummy_socket_filter")
int socket_filter(struct __sk_buff *skb)
{
   return 0;
}
char _license[] SEC("license") = "GPL";
```

```bash
% bpftool prog loadall ./test_kern.o /sys/fs/bpf/test
libbpf: failed to guess program type based on ELF section name 'dummy_socket_filter'
libbpf: supported section(type) names are: socket kprobe/ kretprobe/ classifier action tracepoint/ raw_tracepoint/ xdp perf_event lwt_in lwt_out lwt_xmit lwt_seg6local cgroup_skb/ingress cgroup_skb/egress cgroup/skb cgroup/sock cgroup/post_bind4 cgroup/post_bind6 cgroup/dev sockops sk_skb/stream_parser sk_skb/stream_verdict sk_skb sk_msg lirc_mode2 flow_dissector cgroup/bind4 cgroup/bind6 cgroup/connect4 cgroup/connect6 cgroup/sendmsg4 cgroup/sendmsg6 cgroup/recvmsg4 cgroup/recvmsg6 cgroup/sysctl cgroup/getsockopt cgroup/setsockopt
```

Looks like u need a section name that libbpf can use to discern the correct BPF prog type:


Doing this seems to work:

```bash
% bpftool prog loadall ./test_kern.o /sys/fs/bpf/test type socket

% bpftool prog list
...
223: socket_filter  name socket_filter  tag a04f5eef06a7f555  gpl
        loaded_at 2019-10-19T18:07:54-0500  uid 0
        xlated 16B  jited 32B  memlock 4096B

# ls /sys/fs/bpf/test/
dummy_socket_filter

% bpftool prog dump xlated pinned /sys/fs/bpf/test/dummy_socket_filter
   0: (b7) r0 = 0
   1: (95) exit
```

Looks like this will "pin" the program.  You can use ``bpftool prog pin`` to pin
bpf programs created by other utilities.

```bash
#Using bcc's filetop: /usr/share/bcc/tools/filetop in the background

% bpftool prog list
228: kprobe  name trace_read_entr  tag 6baaf8c2f499a4b8  gpl
        loaded_at 2019-10-19T18:24:51-0500  uid 0
        xlated 856B  jited 470B  memlock 4096B  map_ids 239
229: kprobe  name trace_write_ent  tag 0418f4425b1ffb3c  gpl
        loaded_at 2019-10-19T18:24:51-0500  uid 0
        xlated 856B  jited 470B  memlock 4096B  map_ids 239

% bpftool prog pin id 228 /sys/fs/bpf/test_bcc
% bpftool prog dump xlated pinned /sys/fs/bpf/test_bcc
   0: (79) r2 = *(u64 *)(r1 +96)
   1: (7b) *(u64 *)(r10 -104) = r2
   2: (79) r7 = *(u64 *)(r1 +112)
   3: (85) call bpf_get_current_pid_tgid#97360
   ...
```

Note that if the program has been pinned (to ``/sys/fs/bpf/test_bcc``) and subsequently unattached
(say by killing the ``filetop`` app), the program remains available until deleted.


```bash
% tc qdisc add dev docker0 clsact

% tc filter add dev docker0 ingress bpf obj test_kern.o section dummy_socket_filter
% tc filter show dev docker0 ingress
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 test_kern.o:[dummy_socket_filter] not_in_hw id 233 tag a04f5eef06a7f555 jited
% bpftool prog show
   # This is the original (unused one)
223: socket_filter  name socket_filter  tag a04f5eef06a7f555  gpl
        loaded_at 2019-10-19T18:07:54-0500  uid 0
        xlated 16B  jited 32B  memlock 4096B
   # Here is the one added by tc filter
235: sched_cls  tag a04f5eef06a7f555  gpl
        loaded_at 2019-10-19T18:41:08-0500  uid 0
        xlated 16B  jited 32B  memlock 4096B

# Pin it
% bpftool prog pin id 235 /sys/fs/bpf/tc_filter
# Delete the filter (unaattach from kernel)
% tc filter del dev docker0 ingress
% bpftool prog show
223: socket_filter  name socket_filter  tag a04f5eef06a7f555  gpl
        loaded_at 2019-10-19T18:07:54-0500  uid 0
        xlated 16B  jited 32B  memlock 4096B
      #STILL SHOWS UP
235: sched_cls  tag a04f5eef06a7f555  gpl
        loaded_at 2019-10-19T18:41:08-0500  uid 0
        xlated 16B  jited 32B  memlock 4096B
% ls /sys/fs/bpf/tc_filter
/sys/fs/bpf/tc_filter
% rm /sys/fs/bpf/tc_filter
% bpftool prog show
223: socket_filter  name socket_filter  tag a04f5eef06a7f555  gpl
        loaded_at 2019-10-19T18:07:54-0500  uid 0
        xlated 16B  jited 32B  memlock 4096B
      #ITS GONE NOW
```


*NOTE: I cannot figure out how to get ``tc filter ...`` to take a ``object-pined`` arg



---

## Example: pinning and cgroup eBPF programs

```bash
#Create new cgroup (v2)
mkdir /sys/fs/cgroup/unified/pinnedProg

#Load and pin program (from the kernel bpf samples)
prog load ./tcp_tos_reflect_kern.o /sys/fs/bpf/pinnedProg

#Attach program to cgroup/sock_ops
bpftool cgroup attach /sys/fs/cgroup/unified/pinnedProg sock_ops pinned /sys/fs/bpf/pinnedProg

#Show cgroup attachment
bpftool cgroup list /sys/fs/cgroup/unified/pinnedProg/
	ID       AttachType      AttachFlags     Name
	12873    sock_ops                        bpf_basertt

#Detach program
bpftool cgroup detach /sys/fs/cgroup/unified/pinnedProg sock_ops pinned /sys/fs/bpf/pinnedProg

#Unpin (removes from kernel as there are no more references to the program)
rm /sys/fs/bpf/pinnedProg
```