#include <unistd.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int libbpf_debug_print(enum libbpf_print_level level,
      const char *format, va_list args)
{
   /*Uncomment to not print all debug spam*/
   #if 0
   if (level == LIBBPF_DEBUG)
      return 0;
   #endif
   return vfprintf(stderr, format, args);
}


int main(void)
{
   int prog_fd, perf_fd;
   struct bpf_object *obj;

#if 0
TODO: this is a hack, I manually created this kprobe event like so
   echo "p:kmem_cache_free kmem_cache_free" > /sys/kernel/debug/tracing/kprobe_events
And obtained the ID (this is used to link the kprobe to the BPF program).
   cat /sys/kernel/debug/tracing/events/kprobes/kmem_cache_free/id
#endif
   const int id = 1829;
   int err;
   struct bpf_prog_load_attr prog_attr;

   struct perf_event_attr perf_attr = {};

   perf_attr.type = PERF_TYPE_TRACEPOINT;
   perf_attr.sample_type = PERF_SAMPLE_RAW;
   perf_attr.sample_period = 1;
   perf_attr.wakeup_events = 1;


   memset(&prog_attr, 0, sizeof(struct bpf_prog_load_attr));
   prog_attr.file = "kprobe_kern.o";
   prog_attr.prog_type = BPF_PROG_TYPE_KPROBE;
   prog_attr.log_level = 4;
   libbpf_set_print(libbpf_debug_print);
   err = bpf_prog_load_xattr(&prog_attr, &obj, &prog_fd);
   if (err < 0) {
      printf("Could not load bpf prog: %s\n", strerror(errno));
      return -1;
   }
      
   //TODO: this could all be replaced by "bpf_program__attach_kprobe" from libbpf

   perf_attr.config = id;
   perf_fd = syscall(__NR_perf_event_open, &perf_attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
   if (perf_fd < 0) {
      printf("event %d fd %d err %s\n", id, perf_fd, strerror(errno));
      return -1;
   }
   err = ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
   if (err < 0) {
      printf("ioctl PERF_EVENT_IOC_ENABLE failed err %s\n",
            strerror(errno));
      return -1;
   }
   err = ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
   if (err < 0) {
      printf("ioctl PERF_EVENT_IOC_SET_BPF failed err %s\n",
             strerror(errno));
      return -1;
   }

   while(1)
   {
   }
}


