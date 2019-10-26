#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <sys/types.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include "common.h"


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

int main(int argc, void** argv)
{
   struct bpf_prog_load_attr attr;
   struct bpf_object *obj;
   int prog_fd;
   int err;

   system("rm -r " TAILCALL_PROGS_LOC);

   memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
   attr.file = "tailcall_kern.o";
   attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
   attr.log_level = 4;
   libbpf_set_print(libbpf_debug_print);
   err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);

   //Looks like you dont need to pin, because if you add it to the
   //prog map the kernel keeps it around
   // bpf_object__pin(obj, TAILCALL_PROGS_LOC);
   int prog_array_fd = bpf_obj_get(COMMON_PIN_LOC "/tailcallMap");
   int ind = 0;
   if(argc <= 1)
   {
      printf("Adding tailcall\n");
      err = bpf_map_update_elem(prog_array_fd, &ind, &prog_fd, BPF_ANY);
   }
   else
   {
      printf("Removing tailcall\n");
      err = bpf_map_delete_elem(prog_array_fd, &ind);
   }
   if(err)
   {
      perror("failed:");
   }

   return 0;
}

#if 0

module = bcc.lib.bpf_module_create_c_from_string(b'', True, cflags_array, len(cflags_array), False, None)
table = bcc.lib.bpf_table_fd(module, ct.c_char_p(b'/sys/fs/bpf/my_test/bwMonitorMap'))
// bcc.lib.bpf_table_fd(ct.c_void_p(0), ct.c_char_p(b'/sys/fs/bpf/my_test/bwMonitorMap'))
#endif
