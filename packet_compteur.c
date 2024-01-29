#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>
#include "packet_compteur.skel.h"



int main()
{
    struct packet_compteur_bpf *skel;
    skel = packet_compteur_bpf__open_and_load();
    packet_compteur_bpf__attach(skel);
    int cur_key=0;
    long long value;
    while(true){
        sleep(1);
        bpf_map__lookup_elem(skel->maps.my_config,&cur_key,sizeof(int),&value,sizeof(long long),BPF_ANY);
        printf("mdr nombre paquets : %lld\n",value);
    }
    packet_compteur_bpf__destroy(skel);
    return 0;
}
