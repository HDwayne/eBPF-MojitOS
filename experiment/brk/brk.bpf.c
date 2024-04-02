#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, unsigned long);
    __uint(max_entries, 1);
} perf_map SEC(".maps");

struct s_mystruct
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned long brk;
};

SEC("tp/syscalls/sys_enter_brk")
int brk(struct s_mystruct *ctx){

    //I want to increment the value in the map

    int key = 0;
    unsigned long val = ctx->brk;
    void* val2 = bpf_map_lookup_elem(&perf_map, &key);
    if(val2){
        val = *(unsigned long*)val2 + ctx->brk;
    }
 
    bpf_map_update_elem(&perf_map, &key, &val, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
