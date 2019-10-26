
#include <bcc/BPFTable.h>
#include <memory>
#include <vector>

struct TrafficCounters
{
   std::uint64_t pkts;
   std::uint64_t bytes;
};

class TableReader
{
   using TableType = ebpf::BPFArrayTable<TrafficCounters>;
public:
   TableReader();
   void doPrint();
   void clearCounts();
   std::vector<TrafficCounters> getTable();
   TableReader(TableReader&) = delete;
   TableReader& operator=(TableReader&) = delete;
private:
   std::unique_ptr<TableType> table_ptr = nullptr;
   ebpf::TableDesc tableDesc;
};

