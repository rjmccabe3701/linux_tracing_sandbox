#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#include "common.h"


SEC("this_tailcall")
int socket_filter(struct __sk_buff *skb, struct pt_regs *ctx)
{
   bpf_printk("In tailcall!\n");
   return 0;
}
char _license[] SEC("license") = "GPL";
