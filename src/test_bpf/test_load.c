
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>

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
   struct bpf_prog_load_attr attr;
   struct bpf_object *obj;
   int prog_fd;
   int err;

   memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
   attr.file = "test_kern.o";
   attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
   attr.log_level = 4;
   libbpf_set_print(libbpf_debug_print);
   err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);

   printf("load to kernel = %d, fd = %d\n", err, prog_fd);

   bpf_object__pin(obj, "/sys/fs/bpf/my_test");

   printf("Enter key to exit\n");
   getchar();
   return 0;
}
