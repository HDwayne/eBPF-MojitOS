#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> 
#include <sys/resource.h>
#include <net/if.h>
#include "packet_compteur_egress.skel.h"



static void signaltrap(int sig){
    printf("\nArrêt du programme\n");
    exit(0);
    
}

int main(int argc, char const *argv[])
{
    

    signal(SIGINT,signaltrap);
    libbpf_set_print(NULL);
    float freq;

    if (argc != 4){printf("Error : /%s <flow_type> <frequence> <interface_name> ",argv[0]);return 1;}



    if ((freq=atof(argv[2]))==0){
        return -1;
    }

    struct packet_compteur_egress_bpf *skel;
    skel = packet_compteur_egress_bpf__open_and_load();

    if(!skel){
        printf("Impossible de charger et d'ouvrir le programme dans le kernel\n");
        return -3;
    }


    int fd = bpf_program__fd(skel->progs.tc_test);


    int flow;
    if(strcmp(argv[1],"ingress")==0){
        flow = BPF_TC_INGRESS;
    }
    else if(strcmp(argv[1],"egress")==0){
        flow = BPF_TC_EGRESS;
       
    }else{
        printf("le flow doit être 'ingress' ou 'egress' \n" );
        return -4;
    }

    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = if_nametoindex(argv[3]), .attach_point = flow);
    
	int r = bpf_tc_hook_create(&hook);

    LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
    r = bpf_tc_attach(&hook, &opts);
    if (r < 0)
	{ 
        bpf_tc_hook_destroy(&hook);
	    packet_compteur_egress_bpf__destroy(skel);
        printf("Error while attaching program to the hook \n");return 3;
    }


    
    int cur_key = 0;
    long long value;
    long long time;


    while(true){

        if( bpf_map__lookup_elem(skel->maps.my_config,&cur_key,sizeof(int),&value,sizeof(long long),BPF_ANY) < 0 ){ printf("Erreur lors de la lecture de la map\n");return 6;};
        cur_key++;
        if( bpf_map__lookup_elem(skel->maps.my_config,&cur_key,sizeof(int),&time,sizeof(long long),BPF_ANY) < 0 ) { printf("Erreur lors de la lecture de la map\n");return 6;};
        printf("nombre octets : %lld , time = %lld\n",value,time);
        cur_key=0;
        sleep(1);
    }

    /*opts.prog_fd = opts.prog_id = 0;
	bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
	packet_compteur_egress_bpf__destroy(skel);
    exit(0);*/

    return 0;
}
