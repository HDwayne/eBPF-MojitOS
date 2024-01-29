#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h> 
#include <sys/resource.h>
#include <unistd.h>
#include <net/if.h>
#include "packet_compteur_egress.skel.h"



int main(int argc, char const *argv[])
{
    
    struct packet_compteur_egress_bpf *skel;
    skel = packet_compteur_egress_bpf__open_and_load();
    int fd = bpf_program__fd(skel->progs.tc_test);



    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = if_nametoindex("enp3s0"), .attach_point = BPF_TC_EGRESS);
	/* Create clsact qdisc */
    
	int r = bpf_tc_hook_create(&hook);
	/*if (r < 0)
		{ printf("Error while creating hook \n");return 2;}*/

    LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
    r = bpf_tc_attach(&hook, &opts);
    if (r < 0)
	{ printf("Error while attaching program to the hook \n");return 3;}


    int cur_key=0;
    long long value;
    while(true){
        sleep(1);
        bpf_map__lookup_elem(skel->maps.my_config,&cur_key,sizeof(int),&value,sizeof(long long),BPF_ANY);
        printf("mdr nombre octets : %lld\n",value);
    }
    

	opts.prog_fd = opts.prog_id = 0;
	bpf_tc_detach(&hook, &opts);
    	bpf_tc_hook_destroy(&hook);
	packet_compteur_egress_bpf__destroy(skel);

    return 0;
}
