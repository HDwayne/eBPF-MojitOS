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

    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};


struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,unsigned long);
	__uint(max_entries,2);
} data_mmap SEC(".maps");

SEC("tp/syscalls/sys_enter_mmap")
int mmap(struct s_mystruct *ctx)
{

    
    unsigned long addr = ctx->addr;
	unsigned long bytes_len = ctx->len;

    unsigned long *rec ;
    int key=0;

    rec = bpf_map_lookup_elem(&data_mmap,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }
    //bpf_map_update_elem(&data_mmap,&key,&addr, BPF_ANY);

    __sync_fetch_and_add(rec,addr);

    key++;

    rec = bpf_map_lookup_elem(&data_mmap,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }

    //bpf_map_update_elem(&data_mmap,&key,&bytes_len, BPF_ANY);
    __sync_fetch_and_add((unsigned long*)rec,bytes_len);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";