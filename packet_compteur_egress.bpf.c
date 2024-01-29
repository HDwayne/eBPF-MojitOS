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

SEC("tc")
int tc_test(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	
	long long nb_bits = data_end - data;
	long long *rec = bpf_map_lookup_elem(&my_config,&key);

    	if(!rec){
    		bpf_printk("fuck \n");
        	return 1;
    	}
    	
    	*rec = (*rec)+nb_bits;
    	bpf_printk("miam %lld \n",*rec);
    	
    	
    	return 0;
    	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
