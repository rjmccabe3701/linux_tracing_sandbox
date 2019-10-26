#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#include "common.h"

#if 1
struct bpf_map_def SEC("maps") bwMonitorMap = {
   .type = BPF_MAP_TYPE_ARRAY,
   .key_size = sizeof(__u32),
   .value_size = sizeof(struct traffic_counters),
   .max_entries = 3
};
#endif

struct bpf_map_def SEC("maps") tailcallMap = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1
};

#if 0
Can attach the map via
bpftool prog loadall ./test_kern.o /sys/fs/bpf/test type socket pinmaps /sys/fs/bpf/maps
bpftool map dump pinned /sys/fs/bpf/maps/my_map
#endif

SEC("dummy_socket_filter")
int socket_filter(struct __sk_buff *skb, struct pt_regs *ctx)
{
   int key = 1;
   __u32 len;
   struct traffic_counters* counters = 0;
#if 0
   //This fails verification, because the BPF_PROG_TYPE_SOCKET_FILTER
   // hook apparently doesn't have all the __sk_buff populated.
   void* data = (void*)(long)skb->data;
   void* data_end = (void*)(long)skb->data_end;
   if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
   {
      return 0;
   }

   Looks like the mechanism that checks this is:

   In net/core/filter.c:
      static bool sk_filter_is_valid_access(int off, int size,
            enum bpf_access_type type,
            const struct bpf_prog *prog,
            struct bpf_insn_access_aux *info)
      {
         switch (off) {
            case bpf_ctx_range(struct __sk_buff, tc_classid):
            case bpf_ctx_range(struct __sk_buff, data):
            case bpf_ctx_range(struct __sk_buff, data_meta):
            case bpf_ctx_range(struct __sk_buff, data_end):
            case bpf_ctx_range_till(struct __sk_buff, family, local_port):
            case bpf_ctx_range(struct __sk_buff, tstamp):
            case bpf_ctx_range(struct __sk_buff, wire_len):
               return false;
         }

#endif

   len = skb->len;
   counters = bpf_map_lookup_elem(&bwMonitorMap, &key);

   if(counters)
   {
      __sync_fetch_and_add(&counters->pkts, 1);
      __sync_fetch_and_add(&counters->bytes, skb->len);
   }
   else
   {
      struct traffic_counters val = {1, skb->len};
      bpf_map_update_elem(&bwMonitorMap, &key, &val, BPF_ANY);
   }
   //An ingress_ifindex == 0 means its an outbound pkt
   bpf_printk("pkt len = %lu, ifindex = %lu, ingress_ifindex = %lu\n",
         skb->len, skb->ifindex, skb->ingress_ifindex);

   bpf_tail_call(skb, &tailcallMap, 0);

   bpf_printk("No tailcall registered!\n");
   return 0;
}
char _license[] SEC("license") = "GPL";
