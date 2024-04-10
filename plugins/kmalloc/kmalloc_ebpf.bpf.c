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
	__uint(max_entries,3);
} data_kmalloc SEC(".maps");

SEC("tracepoint/kmem/kmalloc")
int kmalloc(struct s_mystruct *ctx)
{

    
    uint64_t bytes_req = ctx->bytes_req;
	uint64_t bytes_alloc = ctx->bytes_alloc;

    uint64_t *rec ;
    int key=0;

    rec = bpf_map_lookup_elem(&data_kmalloc,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }

    *rec += bytes_req;

     bpf_map_update_elem(&data_kmalloc, &key, rec, BPF_ANY);

    //__sync_fetch_and_add(rec,bytes_req);

    key++;

    rec = bpf_map_lookup_elem(&data_kmalloc,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }

    *rec += bytes_alloc;

     //__sync_fetch_and_add(rec,bytes_alloc);
    bpf_map_update_elem(&data_kmalloc, &key, rec, BPF_ANY);

    key++;

    rec = bpf_map_lookup_elem(&data_kmalloc,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }

    *rec += 1;

    bpf_map_update_elem(&data_kmalloc, &key, rec, BPF_ANY);





    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
