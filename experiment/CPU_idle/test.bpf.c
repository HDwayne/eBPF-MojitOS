#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


//La map qui contiendra en clé le pid du cpu et en valeur le nombre de fois que le cpu a été idle
struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
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

SEC("tp/power/cpu_idle")
int test(struct s_mystruct *ctx){
    
    //petit affichage pour voir si tout fonctionne
    bpf_printk("cpuid :%d\n", ctx->cpu_id);

    __u64 *counter, init_val = 1;
    long long un = 1;
    __u32 pid = ctx->cpu_id;

    //On regarde si le cpu est déjà dans la map
    counter = bpf_map_lookup_elem(&perf_map, &pid);

    //Si oui on incrémente le compteur
    if(counter){
        __sync_fetch_and_add(counter, un);
    }else{
        //Sinon on l'ajoute
        bpf_map_update_elem(&perf_map, &pid, &init_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
