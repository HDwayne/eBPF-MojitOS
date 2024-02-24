#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "network_ebpf.h"


struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,cpt_pckt);
	__uint(max_entries,8);
} my_data_egress SEC(".maps");


struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,int);
	__uint(max_entries,1);
} is_multi_itf_egress SEC(".maps");



SEC("tc")
int tc_test_egress(struct __sk_buff *skb) {
	
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	uint64_t time = bpf_ktime_get_ns();
	uint64_t nb_octets = data_end - data;
	int key=0,* is_one_itf;
	
	if( (is_one_itf = bpf_map_lookup_elem(&is_multi_itf_egress,&key))!=NULL){
		if ( *is_one_itf==0){
			key= skb->ifindex-1;
		}
	}
	else{
		bpf_printk("Erreur : impossible de savoir s'il y a une ou plusieurs interfaces \n");
		return 1;
	}

	cpt_pckt *rec =bpf_map_lookup_elem(&my_data_egress,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }


	__sync_fetch_and_add(&(rec->data[0]),1);
	__sync_fetch_and_add(&(rec->data[1]),nb_octets);
	__sync_fetch_and_add(&(rec->data[2]),bpf_ktime_get_ns() - time);
		
    return 0;
    	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
