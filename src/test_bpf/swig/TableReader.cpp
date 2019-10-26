#include "TableReader.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#include <memory>
#include <bcc/BPFTable.h>
#include <bcc/file_desc.h>
#include "../common.h"

TableReader::TableReader()
   :tableDesc()
{
   tableDesc.name = "nexthop_reader";
   tableDesc.fd = ebpf::FileDesc(bpf_obj_get(COMMON_PIN_LOC "/bwMonitorMap"));
   if(tableDesc.fd < 0)
   {
      throw std::runtime_error("bad map fd!");
   }
   tableDesc.type = BPF_MAP_TYPE_ARRAY;
   tableDesc.key_size = sizeof(uint32_t);
   tableDesc.leaf_size = sizeof(TrafficCounters);
   tableDesc.max_entries = 3;
   table_ptr = std::make_unique<TableType>(tableDesc);
}

void TableReader::doPrint()
{
   while(true)
   {
      auto bwTable = table_ptr->get_table_offline();
      // for(auto& counters: bwTable)
      for(size_t i = 0; i < bwTable.size(); ++i)
      {
         printf("Counters (%ld): pkts = %llu, bytes = %llu\n",
               i, bwTable[i].pkts, bwTable[i].bytes);

         // table_ptr->update_value(i, TrafficCounters{0,0});
      }
      // table_ptr->clear_table_non_atomic();
      printf("\n");
      std::this_thread::sleep_for(std::chrono::seconds{1});
   }
}

std::vector<TrafficCounters> TableReader::getTable()
{
   return table_ptr->get_table_offline();
}


void TableReader::clearCounts()
{
   for(size_t i = 0; i < table_ptr->capacity(); ++i)
   {
      table_ptr->update_value(i, TrafficCounters{0,0});
   }
}


