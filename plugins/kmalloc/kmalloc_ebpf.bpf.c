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

    unsigned long call_site;
    const void *ptr;
    size_t bytes_req;
    size_t bytes_alloc;
    unsigned long gfp_flags;
    int node;
};


struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,uint64_t);
	__uint(max_entries,2);
} data_kmalloc SEC(".maps");

SEC("tracepoint/kmem/kmalloc")
void kmalloc(struct s_mystruct *ctx)
{

    
    uint64_t bytes_req = (uint64_t)ctx->bytes_req;
	uint64_t bytes_alloc = (uint64_t)ctx->bytes_alloc;

    size_t *rec ;

    for ( int key=0 ;  key < 2; key++ ){

        rec = bpf_map_lookup_elem(&data_kmalloc,&key);

        if(!rec){
		    bpf_printk("Erreur : récupération des données dans la map impossible\n");
            return 1;
        }

        if (key==0){
            __sync_fetch_and_add(rec,bytes_req);
        }else{
            __sync_fetch_and_add(rec,bytes_alloc);
        }

    }
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
