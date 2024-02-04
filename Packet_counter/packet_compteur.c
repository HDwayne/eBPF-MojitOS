#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> 
#include <sys/resource.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/bpf.h>
#include "packet_compteur_egress.skel.h"



static void signaltrap(int sig){
    printf("\nArrêt du programme\n");
    exit(0);
    
}

int nb_interface (struct ifaddrs *i){

    int nb = 0;
   
    for(struct ifaddrs *t = i;t!=NULL;t = t->ifa_next){

        if(if_nametoindex(t->ifa_name)<= nb){
            return nb;
        }
        nb++;
    }
    return nb;
}

int main(int argc, char const *argv[])
{
    

    signal(SIGINT,signaltrap);
    libbpf_set_print(NULL);
    float freq;

    if (argc != 3){printf("Error : /%s <flow_type> <frequence> ",argv[0]);return 1;}



    if ((freq=atof(argv[2]))==0){
        return -1;
    }


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


    struct ifaddrs *list_interface;
    if (getifaddrs(&list_interface) < 0) { printf(" Erreur: impossible de récupérer la liste des interfaces réseau du système\n");return -15;}
    int nb_itf = nb_interface(list_interface);


    struct packet_compteur_egress_bpf *skel;
    skel = packet_compteur_egress_bpf__open();


    if(!skel){
        printf("Impossible de charger le programme\n");
        return -3;
    }


    if (bpf_map__set_max_entries(skel->maps.my_octets,nb_itf) <0 || bpf_map__set_max_entries(skel->maps.timeexec,nb_itf) <0){
        printf("miammmm\n");
        return -10;
    }


    if( packet_compteur_egress_bpf__load(skel) < 0){
        printf("ta mère \n"); return 2;
    }

    int fd = bpf_program__fd(skel->progs.tc_test);
    if (!fd){
        printf("aïe !!!\n");
        return -100;
    }

    struct ifaddrs *itf;int r;

    int c=0,index;
    for( itf = list_interface; c<nb_itf; itf = itf->ifa_next){
        index = if_nametoindex(itf->ifa_name);

        LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = index, .attach_point = flow);

        r = bpf_tc_hook_create(&hook);

        LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
        r = bpf_tc_attach(&hook, &opts);
        if (r < 0)
	    { 
            bpf_tc_hook_destroy(&hook);
            freeifaddrs(list_interface);
	        packet_compteur_egress_bpf__destroy(skel);
            printf("Error while attaching program to the hook \n");
            return 3;
        }
        c++;
    }


    int cur_key;
    long long value;
    long long time;


    while(true){
        
        cur_key = 0;
        for( itf = list_interface; cur_key<nb_itf; itf = itf->ifa_next){
        

            if( bpf_map__lookup_elem(skel->maps.my_octets,&cur_key,sizeof(int),&value,sizeof(long long),BPF_ANY) < 0 ){ printf("Erreur lors de la lecture de la map\n");return 6;};
            if( bpf_map__lookup_elem(skel->maps.timeexec,&cur_key,sizeof(int),&time,sizeof(long long),BPF_ANY) < 0 ) { printf("Erreur lors de la lecture de la map\n");return 6;};
            printf("interface : %s , nombre octets : %lld , time = %lld\n",itf->ifa_name,value,time);
            cur_key++;

        }
        printf("\n");
        sleep(freq);
    }




/*TODO*/

cleanup:
	

    freeifaddrs(list_interface);
    packet_compteur_egress_bpf__destroy(skel);

    return 0;
}
