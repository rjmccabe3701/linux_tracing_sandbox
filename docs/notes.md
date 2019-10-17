

The ``trace -s`` tool (same as ``perf trace``) is pretty neat:

```
-> # trace  -s
^C
 Summary of events:

 docker-containe (2053), 46 events, 7.3%

   syscall            calls    total       min       avg       max      stddev
                               (msec)    (msec)    (msec)    (msec)        (%)
   --------------- -------- --------- --------- --------- ---------     ------
   futex                  8   998.771     0.000   124.846   423.396     42.61%
   pselect6              15     1.226     0.078     0.082     0.099      1.72%


 docker-containe (2069), 26 events, 4.1%

   syscall            calls    total       min       avg       max      stddev
                               (msec)    (msec)    (msec)    (msec)        (%)
   --------------- -------- --------- --------- --------- ---------     ------
   futex                  6   773.142     0.000   128.857   500.676     67.23%
   pselect6               2     0.121     0.055     0.061     0.066      9.14%
   epoll_pwait            5     0.052     0.003     0.010     0.039     68.35%
...
```

perf stat --per-thread



NEAT:

``bpftool prog dump xlated id 97 visual file`` outputs a DOT file of the BPF prog
flowgraph

# Uprobe


Looks like the ``strlen_count.py`` sample goes this:

```python
   b.attach_uprobe(name="/home/rjmccabe/linux_sandbox/bcc/examples/tracing/a.out", sym="mystrlen", fn_name="count")
```

Which attaches a uprobe:


```c++
   StatusTuple BPF::attach_uprobe(const std::string& binary_path,
      // ...
     TRY2(load_func(probe_func, BPF_PROG_TYPE_KPROBE, probe_fd));
     int res_fd = bpf_attach_uprobe(probe_fd, attach_type, probe_event.c_str(),
                                    binary_path.c_str(), offset, pid);

   /*
    * new kernel API allows creating [k,u]probe with perf_event_open, which
    * makes it easier to clean up the [k,u]probe. This function tries to
    * create pfd with the new API.
    */
```


# libbcc

How does this relate to the kernels tools/lib/bpf/libbpf.h?


# bpftool:

```

-> # bpftool prog help
Usage: bpftool prog { show | list } [PROG]
       bpftool prog dump xlated PROG [{ file FILE | opcodes | visual }]
       bpftool prog dump jited  PROG [{ file FILE | opcodes }]
       bpftool prog pin   PROG FILE
       bpftool prog load  OBJ  FILE [type TYPE] [dev NAME] \
                         [map { idx IDX | name NAME } MAP]
       bpftool prog help

       MAP := { id MAP_ID | pinned FILE }
       PROG := { id PROG_ID | pinned FILE | tag PROG_TAG }
       TYPE := { socket | kprobe | kretprobe | classifier | action |
                 tracepoint | raw_tracepoint | xdp | perf_event | cgroup/skb |
                 cgroup/sock | cgroup/dev | lwt_in | lwt_out | lwt_xmit |
                 lwt_seg6local | sockops | sk_skb | sk_msg | lirc_mode2 |
                 cgroup/bind4 | cgroup/bind6 | cgroup/post_bind4 |
                 cgroup/post_bind6 | cgroup/connect4 | cgroup/connect6 |
                 cgroup/sendmsg4 | cgroup/sendmsg6 }
       OPTIONS := { {-j|--json} [{-p|--pretty}] | {-f|--bpffs} }


```

Can also "dump" maps:

```
bpftool map dump id 111
```

https://git.netfilter.org/


# Iptables and pinning

See the linux/samples/bpf/cookie_uid_helper.example.c:


```
-> # iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy DROP)
target     prot opt source               destination
...

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere            match bpf pinned /tmp/tmp.fl2jS7zuy8/bpf_prog

...
```


# BCC filter tool:

```c
int rob_func(int i)
{
   return i+2;
}

int main(void)
{
   while(1)
      rob_func(2);
}
```

```
-> # ./funccount -p $(pidof a.out) '/home/rjmccabe/linux_sandbox/scratch/a.out:*'
Tracing 11 functions for "/home/rjmccabe/linux_sandbox/scratch/a.out:*"... Hit Ctrl-C to end.
^C
FUNC                                    COUNT
rob_func                              2260268
Detaching...
```


```
trace 't:sched:sched_wakeup (STRCMP("sshd", args->comm)) "process = %s", args->comm' -T

TIME     PID     TID     COMM            FUNC             -
15:29:07 9946    9946    kworker/u24:0   sched_wakeup     process = sshd
15:29:13 0       0       swapper/4       sched_wakeup     process = sshd
```


# USDT:

```
-> # ./tplist -l /lib/x86_64-linux-gnu/libc-2.27.so
/lib/x86_64-linux-gnu/libc-2.27.so libc:setjmp
/lib/x86_64-linux-gnu/libc-2.27.so libc:longjmp
/lib/x86_64-linux-gnu/libc-2.27.so libc:longjmp_target
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_arena_max
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_arena_test
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tunable_tcache_max_bytes
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tunable_tcache_count
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tunable_tcache_unsorted_limit
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_trim_threshold
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_top_pad
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_mmap_threshold
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_mmap_max
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_perturb
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_new
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_sbrk_less
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_reuse
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_reuse_wait
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_new
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_reuse_free_list
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_retry
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_free
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_less
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_more
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_sbrk_more
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_free_dyn_thresholds
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_malloc_retry
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_memalign_retry
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_realloc_retry
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_calloc_retry
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt
/lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_mxfast
/lib/x86_64-linux-gnu/libc-2.27.so libc:lll_lock_wait_private
```

Creating your own:

https://lwn.net/Articles/753601/


```c
#include <sys/sdt.h>
#include <sys/time.h>
#include <unistd.h>
int rob_func(int i)
{
   struct timeval tv;
   gettimeofday(&tv, NULL);
   DTRACE_PROBE1(test-app, test-probe, tv.tv_sec);
   return i+2;
}


int main(void)
{
   while(1)
      rob_func(2);
}

```

``./trace 'u:/home/rjmccabe/linux_sandbox/scratch/a.out:test-probe "%u", arg1' -T -p $(pidof a.out)``

Return probe on arbitary C method:

```
./trace 'r:/home/rjmccabe/linux_sandbox/scratch/a.out:rob_func "ret = %d", retval' -T -p $(pidof a.out)
#OR if using C++
/
/
```


-----

Entering docker network namespace:

 nsenter -t 32646 -n ss -lp
 nsenter -t 32646 -n tcpdump -i eth0 -ln

 OR

nsenter --net=/run/netns/ns2 <command>

Where /run/netns/ns2 is a pinned namespace file (could be created by ``sudo ip netns add ns1``)


----------------

Tracing tcp connections:


```
-> # ./tcptracer  -v
Tracing TCP established connections. Ctrl-C to end.
TYPE         PID    COMM             IP SADDR            DADDR            SPORT  DPORT  NETNS
close        2570   nc               4  172.17.0.1       172.17.0.2       52502  12345  4026532008
close        2557   nc               4  172.17.0.2       172.17.0.1       12345  52502  4026532747

#Tracing particular namespace (/proc/<pid/ns/ ...)
-> # ./tcptracer  -v -N 4026532747
Tracing TCP established connections. Ctrl-C to end.
TYPE         PID    COMM             IP SADDR            DADDR            SPORT  DPORT
accept       2991   nc               4  172.17.0.2       172.17.0.1       12345  52510

#Show when process starts listening
-> # ./solisten --show-netns
PID    COMM         NETNS        PROTO  BACKLOG  PORT  ADDR
3151   nc           4026532747   TCPv4  1        12345 0.0.0.0


```

Tracing what a stuck process is doing:
```
Tracing syscalls, printing top 10... Ctrl+C to quit.
^C[12:09:44]
SYSCALL                   COUNT
select                      766
poll                         78

Detaching...

```


## Getting iproute2 to recognize docker-generated network namespaces

See this:
   https://platform9.com/blog/container-namespaces-deep-dive-container-networking/

Basically you just identify the PID for your container

```
   sudo ln -sf /proc/$(docker inspect -f '{{.State.Pid}}' "host-2")/ns/net /var/run/netns/host-2
```

Now you can do this:

```
   sudo ip netns exec host-2 ip address show
```







