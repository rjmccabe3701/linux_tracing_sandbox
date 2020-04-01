# Adventures of BCC with Docker containers

## Cgroup filter isn't quite there yet ...

It would be nice if bcc has some sort of global ``--filter-by-docker-container`` option.

I do notice there is ``-c cgroup_path`` option for the bcc ``trace.py`` utility.  However this doesn't seem to work:

```bash
% sudo ./trace -v -c /sys/fs/cgroup/systemd/docker/eeabaee9c25894e93be596238ad2f62f1b9ef613e9e0f23ce918fd5cc03e4f03 t:syscalls:sys_enter_clone

Traceback (most recent call last):
  File "./trace", line 868, in run
    self._attach_probes()
  File "./trace", line 839, in _attach_probes
    cgroup_array[0] = self.args.cgroup_path
  File "/usr/lib/python2.7/dist-packages/bcc/table.py", line 570, in __setitem__
    super(CgroupArray, self).__setitem__(key, self.Leaf(f.fd))
  File "/usr/lib/python2.7/dist-packages/bcc/table.py", line 489, in __setitem__
    super(ArrayBase, self).__setitem__(key, leaf)
  File "/usr/lib/python2.7/dist-packages/bcc/table.py", line 257, in __setitem__
    raise Exception("Could not update table: %s" % errstr)
Exception: Could not update table: Bad file descriptor

```

It doesn't seem to be a version version thing because I get this same error for versions 4.15 and 5.3.  However, even if it did work,
this only is an option for the ``trace.py`` utility.  Hopefully the BCC team will add cgroup filtering to all their tools in the future.

## Userspace tracing

Here is an example of tracing calls to ``malloc`` inside a docker container:

```
% CONTAINER_NAME=<someContainer>
% CONTAINER_PID=$(docker inspect $CONTAINER_NAME  | jq '.[0].State.Pid')
% sudo ./funccount -i 1 /proc/$CONTAINER_PID/root//lib/x86_64-linux-gnu/libc-2.27.so:malloc                                                    Tracing 1 functions for "/proc/10116/root//lib/x86_64-linux-gnu/libc-2.27.so:malloc"... Hit Ctrl-C to end.

FUNC                                    COUNT
malloc                                  67216
^C
FUNC                                    COUNT
Detaching...


```


Trying to figure out why system calls are failing for a process:

```bash
-> % sudo ./syscount -x -p 17869
Tracing failed syscalls, printing top 10... Ctrl+C to quit.
^C[23:35:40]
SYSCALL                   COUNT
openat                      951
stat                        896

-> % sudo ./trace -p 17869   \
   't:syscalls:sys_enter_newstat "filename = %s", args->filename' \
   't:syscalls:sys_exit_newstat (args->ret < 0) "bad stat ret = %d", args->ret'
```

This shows the USDT probes for a process in the docker container:

```
-> % sudo ./tplist -p 23764
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan2
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan2_inexact
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowlog_inexact
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowlog
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan_inexact
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowtan
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowasin
/proc/23764/root/lib/x86_64-linux-gnu/libm-2.27.so libm:slowacos
/proc/23764/root/lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_acquired
...
```

