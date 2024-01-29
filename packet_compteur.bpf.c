#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>



struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, long long) ;
        __uint(max_entries, 1);
} my_config SEC(".maps");

int key = 0;
SEC("xdp")
int cpt_paquet(struct xdp_md *ctx) {

    void *data_end= (void*)(long)ctx->data_end;
    void *data= (void*)(long)ctx->data;

    long long nb_bits = data_end - data;

    long long *rec = bpf_map_lookup_elem(&my_config,&key);

    if(!rec){
    	bpf_printk("fuck \n");
        return XDP_ABORTED;
    }


    *rec = (*rec)+nb_bits;
    bpf_printk("miam %lld \n",*rec);
    
    //bpf_map_update_elem(&my_config, &key,&count,BPF_ANY);
  
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

