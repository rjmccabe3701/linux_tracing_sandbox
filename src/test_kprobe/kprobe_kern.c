#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
int bpf_prog1(struct pt_regs *ctx)
{
   long ptr = PT_REGS_PARM2(ctx);
   bpf_printk("My kprobe!\n");
   return 0;
}

char _license[] SEC("license") = "GPL";
