#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "network_ebpf.h"






struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,cpt_pckt);
	__uint(max_entries,1);
} my_data SEC(".maps");



SEC("tc")
int tc_test(struct __sk_buff *skb) {
	
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	uint64_t time = bpf_ktime_get_ns();
	uint64_t nb_octets = data_end - data;
	int key = skb->ifindex-1;
	cpt_pckt *rec =bpf_map_lookup_elem(&my_data,&key);

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }

	bpf_printk("%ld \n",rec->data[0]);

	//if( skb->flow_keys->flow_label == 1){
		 __sync_fetch_and_add(&(rec->data[0]),1);
		 __sync_fetch_and_add(&(rec->data[1]),nb_octets);
		 rec->data[4] = bpf_ktime_get_ns() - time;
		 /*if (bpf_map_update_elem(&my_data,&key,rec,BPF_ANY) < 0){
			bpf_printk("Erreur : update de la map impossible \n");
			return 3;
		 }*/
	bpf_printk("%ld \n",rec->data[0]);

	//}else{
		__sync_fetch_and_add(&(rec->data[2]),1);
		__sync_fetch_and_add(&(rec->data[3]),nb_octets);
		rec->data[5] = bpf_ktime_get_ns() - time;
		/*if (bpf_map_update_elem(&my_data,&key,rec,BPF_ANY) < 0){
			bpf_printk("Erreur : update de la map impossible \n");
			return 3;
		}*/
	//}
    
	
    	
    return 0;
    	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
