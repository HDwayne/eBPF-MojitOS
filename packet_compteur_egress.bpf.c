#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>



struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, int);
        __type(value, long long) ;
        __uint(max_entries, 2);
} my_config SEC(".maps");


SEC("tc")
int tc_test(struct __sk_buff *skb) {
	int key = 0;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	long long time = bpf_ktime_get_ns();
	long long nb_bits = data_end - data;
	long long *rec =bpf_map_lookup_elem(&my_config,&key);
	

    if(!rec){
		bpf_printk("merdouille\n");
        return 1;
    }
    
    __sync_fetch_and_add(rec,nb_bits);
	/*int r = bpf_map_update_elem(&my_config,&key,rec,BPF_ANY);
	if (r<0){
		bpf_printk("mdr 3\n");
		return 2;
	}*/

	key++;

	
	time = bpf_ktime_get_ns() - time;
	int r = bpf_map_update_elem(&my_config,&key,&time,BPF_ANY);
	if (r<0){
		bpf_printk("mdr 4\n");
		return 3;
	}
	
    	
    return 0;
    	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
