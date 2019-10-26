#pragma once
struct traffic_counters
{
  __u64 pkts;
  __u64 bytes;
};

#define COMMON_PIN_LOC "/sys/fs/bpf/my_test"
#define TAILCALL_PROGS_LOC "/sys/fs/bpf/my_tailcalls"
