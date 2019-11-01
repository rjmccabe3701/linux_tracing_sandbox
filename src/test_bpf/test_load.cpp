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

#include <chrono>
#include <thread>
#ifdef SHOW_TRAFFIC_STATS
#include <bcc/BPFTable.h>
#include <bcc/file_desc.h>
#endif

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
   int sock_fd = -1;
   struct sockaddr_ll sll;

   system("rm -r " COMMON_PIN_LOC);

   memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
   attr.file = "test_kern.o";
   attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
   attr.log_level = 4;
   libbpf_set_print(libbpf_debug_print);
   err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);

   printf("load to kernel = %d, fd = %d\n", err, prog_fd);

   bpf_object__pin(obj, COMMON_PIN_LOC);


   sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
   assert(sock_fd >= 0);

// #define IFACE "ens1f0"
#define IFACE "eth0"
/* #define IFACE "docker0" */

   //The SO_ATTACH_FILTER requires the bpf instructions buffer, but this
   // isn't available in the libbpf public iface
   /* err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, & */
   err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
   assert(err == 0);
   memset(&sll, 0, sizeof(sll));
   sll.sll_family = AF_PACKET;
   sll.sll_ifindex = if_nametoindex(IFACE);
   assert(sll.sll_ifindex > 0);
   sll.sll_protocol = htons(ETH_P_ALL);
   if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
      printf("bind to %s: %s\n", IFACE, strerror(errno));
      close(sock_fd);
      return -1;
   }
#ifdef SHOW_TRAFFIC_STATS
   ebpf::TableDesc tableDesc;
   tableDesc.name = "nexthop_reader";
   tableDesc.fd = ebpf::FileDesc(bpf_object__find_map_fd_by_name(obj, "bwMonitorMap"));
   tableDesc.type = BPF_MAP_TYPE_ARRAY;
   tableDesc.key_size = sizeof(uint32_t);
   tableDesc.leaf_size = sizeof(traffic_counters);
   tableDesc.max_entries = 3;

   ebpf::BPFArrayTable<traffic_counters> table(tableDesc);
   while(true)
   {
      auto bwTable = table.get_table_offline();
      // for(auto& counters: bwTable)
      for(size_t i = 0; i < bwTable.size(); ++i)
      {
         printf("Counters (%ld): pkts = %llu, bytes = %llu\n",
               i, bwTable[i].pkts, bwTable[i].bytes);

         // table.update_value(i, traffic_counters{0,0});
      }
      printf("\n");
      std::this_thread::sleep_for(std::chrono::seconds{1});
   }
#else
   printf("Enter key to exit\n");
   getchar();
#endif
   return 0;
}


///nsenter -n -t 8894 ./test_load.exe
