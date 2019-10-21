#include <linux/bpf.h>
/* #include <linux/if_ether.h> */
/* #include <linux/pkt_cls.h> */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
/* #include "bpf/bpf.h" */
#define PIN_GLOBAL_NS		2

#if 1
struct bpf_map_def SEC("maps") my_map = {
   .type = BPF_MAP_TYPE_ARRAY,
   .key_size = sizeof(int),
   .value_size = sizeof(int),
   .max_entries = 1
};
#endif

#if 0
Can attach the map via
bpftool prog loadall ./test_kern.o /sys/fs/bpf/test type socket pinmaps /sys/fs/bpf/maps
bpftool map dump pinned /sys/fs/bpf/maps/my_map
#endif



SEC("dummy_socket_filter")
int socket_filter(struct __sk_buff *skb)
{
#if 1
   int key = 0;
   int init_val = 1;
   int *value;
   char fmt[] = "non zero value";
   char fmt2[] = "zero value";
   /* bpf_map_update_elem(&my_map, &key, &init_val, BPF_ANY); */
   value = bpf_map_lookup_elem(&my_map, &key);
   if (value)
      bpf_trace_printk(fmt, sizeof(fmt));
   else
      bpf_trace_printk(fmt2, sizeof(fmt2));
#endif

   return 0;
}
char _license[] SEC("license") = "GPL";
