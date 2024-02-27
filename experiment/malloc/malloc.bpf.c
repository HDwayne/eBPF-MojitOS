#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>




struct vmalloc_ctx{

	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	unsigned long addr;
	unsigned long size;
	unsigned long align;
	unsigned long vstart;
	unsigned long vend;
	int failed;

};


struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,unsigned long);
	__uint(max_entries,1);
} data_vmalloc SEC(".maps");




SEC("tp/vmalloc/alloc_vmap_area")
int tc_test(struct vmalloc_ctx *ctx) {

	unsigned long val = ctx->size;
	int key = 0;
	unsigned long *res = bpf_map_lookup_elem(&data_vmalloc, &key);

	if (!res){
		bpf_printk("Erreur : impossible d'accéder à la map");
		return 1;
	}

	__sync_fetch_and_add(res,val);

	return 0;
	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
