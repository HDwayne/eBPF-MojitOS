#include <inttypes.h>
#include <info_reader.h>

static char *ebpf_counters[] = {
    "ebpf_cpu_frequency",
    "ebpf_mmap"
};

#define NB_COUNTERS 2