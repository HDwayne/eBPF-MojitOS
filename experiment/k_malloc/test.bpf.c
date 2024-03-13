#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


//La map qui contiendra en clé le pid du cpu et en valeur le nombre de fois que le cpu a été idle
struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} perf_map SEC(".maps");

struct s_mystruct
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned long call_site;
    const void *ptr;
    size_t bytes_req;
    size_t bytes_alloc;
    unsigned long gfp_flags;
    int node;
};

SEC("tp/kmem/kmalloc")
int test(struct s_mystruct *ctx){

    //I want to increment the value in the map

    int key = 0;
    int val = 1;
    void* val2 = bpf_map_lookup_elem(&perf_map, &key);
    if(val2){
        val = *(int*)val2 + 1;
    }

        
    bpf_map_update_elem(&perf_map, &key, &val, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
