# Random eBPF notes

## Tracking down bug in ``samples/bpf/test_map_in_map_kern.c``

I was trying to understand eBPF's "map-in-maps" by running ``linux/samples/bpf/test_map_in_map``.
I get this error:

```
test_map_in_map: samples/bpf/test_map_in_map_user.c:94: test_map_in_map: Assertion `!ret' failed.
```

To track this down I figured used ``perf ftrace`` to find out why the ``bpf_map_lookup_elem`` is failing (it eventually
calls into the kernel ``map_lookup_elem`` method):

```
root@gauss:/home/rjmccabe/linux_tracing_sandbox# perf ftrace -a  --tracer=function_graph -G map_lookup_elem -D 8 --nograph-funcs=smp_irq_work_interrupt
  9)               |  map_lookup_elem() {
[...]
  9)               |    htab_map_lookup_elem() {
  9)               |      __htab_map_lookup_elem() {
  9)   0.269 us    |        lookup_nulls_elem_raw(); ---> THERE IS NOTHING AT THIS KEY
  9)   0.920 us    |      }
  9)   1.471 us    |    }
  9) + 30.891 us   |  }
```

I also wanted to play around with the nifty bpftrace tool (for no other reason other than I thought it's neat):

```
-> % sudo bpftrace -e 'kretprobe:map_lookup_elem /retval != 0/ { printf("bad retval = %d\n", retval) }'
Attaching 1 probe...
bad retval = -2
```

Looking thru ``test_map_in_map_kern.c`` I think the intention is for the ``trace_sys_connect`` eBPF program to set these
hash entries.  However it looks like it's not being directed to the correct kernel call:

```
root@gauss:/home/rjmccabe/linux_tracing_sandbox# perf ftrace -p 1337832  --tracer=function_graph -G __x64_sys_connect -D 8 --nograph-funcs=smp_irq_work_interrupt
 35)               |  __x64_sys_connect() {
 35)               |    __sys_connect() {  ---> DOESN'T CALL sys_connect
 35)               |      sockfd_lookup_light() {
 35)               |        __fdget() {
 35)   0.665 us    |          __fget_light();
 35)   1.795 us    |        }
 35)   2.817 us    |      }
 35)   4.333 us    |    }
 35) + 18.493 us   |  }
 ```

It's currently this
```c
SEC("kprobe/sys_connect")
int trace_sys_connect(struct pt_regs *ctx)
{
  //...
}
```

Changing it to this works:

```c
SEC("kprobe/__sys_connect")
int trace_sys_connect(struct pt_regs *ctx)
{
  //...
}
```


Looks like this commit is what broke it

```git
tree 776bab696932ecd185bbcfeee762e5f7ab2b2bb2
parent a87d35d87a3e4f2a0b0968d1f06703c909138b62
author Dominik Brodowski <linux@dominikbrodowski.net> Tue Mar 13 19:35:09 2018 +0100
committer Dominik Brodowski <linux@dominikbrodowski.net> Mon Apr 2 20:15:08 2018 +0200

net: socket: add __sys_connect() helper; remove in-kernel call to syscall

Using the net-internal helper __sys_connect() allows us to avoid the
internal calls to the sys_connect() syscall.

This patch is part of a series which removes in-kernel calls to syscalls.
On this basis, the syscall entry path can be streamlined. For details, see
http://lkml.kernel.org/r/20180325162527.GA17492@light.dominikbrodowski.net

```

I probably should push a fix, but I don't have the energy at the momemt.  From the ``submitting-patches.rst``
kernel doc, apparently I have to send the patch to one of these dudes:

```
-> % scripts/get_maintainer.pl -f samples/bpf/test_map_in_map_kern.c
Alexei Starovoitov <ast@kernel.org> (supporter:BPF (Safe dynamic programs and tools))
Daniel Borkmann <daniel@iogearbox.net> (supporter:BPF (Safe dynamic programs and tools))
Martin KaFai Lau <kafai@fb.com> (reviewer:BPF (Safe dynamic programs and tools))
Song Liu <songliubraving@fb.com> (reviewer:BPF (Safe dynamic programs and tools))
Yonghong Song <yhs@fb.com> (reviewer:BPF (Safe dynamic programs and tools))
Andrii Nakryiko <andriin@fb.com> (reviewer:BPF (Safe dynamic programs and tools))
netdev@vger.kernel.org (open list:BPF (Safe dynamic programs and tools))
bpf@vger.kernel.org (open list:BPF (Safe dynamic programs and tools))
linux-kernel@vger.kernel.org (open list)
```
---

## Interacting with another process's eBPF maps/programs

**Question:** how does bpftool query programs and maps without file descriptors and things being pinned?

**Answer:** looks like there are some extra (undocumented in the manpage) ``bpf()`` syscall
directives for walking existing BPF entities:

```c
//tools/lib/bpf/bpf.c
static int bpf_obj_get_next_id(__u32 start_id, __u32 *next_id, int cmd)
{
	union bpf_attr attr;
	int err;

	memset(&attr, 0, sizeof(attr));
	attr.start_id = start_id;

  //THIS RETURNS AN "ID" (not file descriptor) TO BE USED BY SUBSEQUENT
  // CALLS TO bpf_map_get_fd_by_id (see below)
	err = sys_bpf(cmd, &attr, sizeof(attr));
	if (!err)
		*next_id = attr.next_id;

	return err;
}

int bpf_prog_get_next_id(__u32 start_id, __u32 *next_id)
{
	return bpf_obj_get_next_id(start_id, next_id, BPF_PROG_GET_NEXT_ID);
}

int bpf_map_get_next_id(__u32 start_id, __u32 *next_id)
{
	return bpf_obj_get_next_id(start_id, next_id, BPF_MAP_GET_NEXT_ID);
}

//...
int bpf_map_get_fd_by_id(__u32 id)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_id = id;
  //This returns a new file descriptor handle to be used by the
  //caller to interact with the map/prog
	return sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

```
---

## eBPF map in maps

When creating a ``MAP_TYPE_HASH_OF_MAPS`` or ``MAP_TYPE_ARRAY_OF_MAPS``
you need to pass an **inner_map_fd** template the the inner maps you wish
to store.  Note that, upon creation of this *outer map* there will be no valid entries.  You will still need to update the key (with a valid map that matches the template)

```c
//This is called from the bpf(BPF_MAP_CREATE, ...) syscall
static struct bpf_map *array_of_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map, *inner_map_meta;
  //Store the template (metadata) from inner_map_fd for later validation
	inner_map_meta = bpf_map_meta_alloc(attr->inner_map_fd);
	if (IS_ERR(inner_map_meta))
		return inner_map_meta;

	map = array_map_alloc(attr);
	if (IS_ERR(map)) {
		bpf_map_meta_free(inner_map_meta);
		return map;
	}

	map->inner_map_meta = inner_map_meta;

	return map;
}
```

This is how you add inner maps:

```c
/* only called from syscall */
int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
				 void *key, void *value, u64 map_flags)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	void *new_ptr, *old_ptr;
	u32 index = *(u32 *)key, ufd;

	if (map_flags != BPF_ANY)
		return -EINVAL;

	if (index >= array->map.max_entries)
		return -E2BIG;

	ufd = *(u32 *)value;
  //This call:
  // * checks to see if the new inner map (referenced by "ufd") is
  //   of the same "type" as the template inner map (specified upon
  //   creation of the outer map)
  // * Adds a reference count to this inner map
	new_ptr = map->ops->map_fd_get_ptr(map, map_file, ufd);
	if (IS_ERR(new_ptr))
		return PTR_ERR(new_ptr);

  //This writes the inner map at the specified key
	old_ptr = xchg(array->ptrs + index, new_ptr);
	if (old_ptr)
		map->ops->map_fd_put_ptr(old_ptr);

	return 0;
}
```

From the ``BPF_MAP_LOOKUP_ELEM`` syscall it calls

```c
		ptr = map->ops->map_lookup_elem(map, key);
```

Which is``.map_lookup_elem = array_of_map_lookup_elem`` for an array of maps

```c
//kernel/bpf/arraymap.c
static void *array_of_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map = array_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}

/* Called from syscall or from eBPF program */
static void *array_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

  //will return NULL if no inner map exists at this index
	return array->value + array->elem_size * (index & array->index_mask);
}
```
