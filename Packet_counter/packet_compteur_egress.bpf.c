#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>



struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,long long);
	__uint(max_entries,1);
} my_octets SEC(".maps");


struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__type(key,int);
	__type(value,long long);
	__uint(max_entries,1);
} timeexec SEC(".maps");




SEC("tc")
int tc_test(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	long long time = bpf_ktime_get_ns();
	long long nb_bits = data_end - data;
	int key = skb->ifindex-1;
	long long *rec =bpf_map_lookup_elem(&my_octets,&key);
	

    if(!rec){
		bpf_printk("Erreur : récupération des données dans la map impossible\n");
        return 1;
    }
    
    __sync_fetch_and_add(rec,nb_bits);


	time = bpf_ktime_get_ns() - time;
	int r = bpf_map_update_elem(&timeexec,&key,&time,BPF_ANY);
	if (r<0){
		bpf_printk("Erreur : update de la map impossible \n");
		return 3;
	}


	bpf_printk("itf : %d value : %d time: %d\n",skb->ifindex,*rec,time);
	
    	
    return 0;
    	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
