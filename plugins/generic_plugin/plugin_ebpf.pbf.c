/*This code has to be included in ../src_ebpf/*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct s_mystruct
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    /* here, you have to place the structure in
    sudo cat /sys/kernel/debug/tracing/events/.../.../format
    */
};

/* here is the map of the programme, you just have to modify the type of the value, the type of the key and the maximum number of entry of the map*/
struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,int);
	__uint(max_entries,2);
} data_kmalloc SEC(".maps");

/* here is the function that will be called when the tracepoint is triggered
you have to place the type and the name of the tracepoint */
SEC("tracepoint/.../...")
void function(struct s_mystruct *ctx)
{

    /* here you can make what you want that will be trigger by the tracepoint
    for example, you can update the map with :

    int key = ctx->...;
    int val = ctx->...;
    
    bpf_map_update_elem(&perf_map, &key, &val, BPF_ANY);
    */
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
