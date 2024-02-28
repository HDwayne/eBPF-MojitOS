#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


//La map qui contiendra en clé le pid du cpu et en valeur le nombre de fois que le cpu a été idle
struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 16);
} perf_map SEC(".maps");

//La fonction qui sera appelée à chaque fois que le cpu est idle
struct s_mystruct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    __u32 state;
    __u32 cpu_id;
};

SEC("tp/power/cpu_frequency")
int test(struct s_mystruct *ctx){

    __u32 pid = ctx->cpu_id;
    __u32 val = ctx->state;
    
    bpf_map_update_elem(&perf_map, &pid, &val, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
