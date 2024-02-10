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



typedef struct monitoring_hook {
    struct bpf_tc_hook ingress;
    struct bpf_tc_hook egress;
}m_hook;



int fin=0;
// catch le signal pour terminé proprement
static void signaltrap(int sig){
    fin=1;

}


// enlève l'ensemble des hooks des interfaces
void destroy_tab_hook_tc (m_hook *tab_hook,int nb_itf){
    for(int i=0; i<nb_itf;i++ ){

        LIBBPF_OPTS(bpf_tc_opts, opts);
        opts.prog_fd = opts.prog_id = 0;
        bpf_tc_detach(&(tab_hook[i].ingress),&opts);
        bpf_tc_detach(&(tab_hook[i].egress),&opts);
       
    }
   
}



// Créer un hook
int create_hook_tc(m_hook *tab_hook,int i,int flow,int index,int fd){
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = index, .attach_point = flow );

    int r = bpf_tc_hook_create(&hook);

    LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
        
    r = bpf_tc_attach(&hook, &opts);
    if (r < 0)
	{ 
        return r;
          
    }

    if(flow == BPF_TC_INGRESS){
        tab_hook[i].ingress = hook;
    }
    else{
        tab_hook[i].egress = hook;
    }
    return 0;

}


// Remplit le tableau tab_hook de hooks
int create_tab_hook_tc ( int fd, int nb_itf, m_hook *tab_hook,struct ifaddrs *list_interface){

    int index,c=0;struct ifaddrs *itf;
    for( itf = list_interface; c<nb_itf; itf = itf->ifa_next){
        index = if_nametoindex(itf->ifa_name);
        if (create_hook_tc(tab_hook,c,BPF_TC_INGRESS,index,fd) <0 || create_hook_tc(tab_hook,c,BPF_TC_EGRESS,index,fd) <0 ){
            return c;
        }
        c++;
    }
    return -1;

}


// Calcul le nombre d'interface
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



// cleanup lors d'une erreur en début de programme
void cleanup_error_early(struct packet_compteur_egress_bpf *skel){
    packet_compteur_egress_bpf__detach(skel);
    packet_compteur_egress_bpf__destroy(skel);
    exit(errno);
}



// cleanup en fin de programme
void cleanup_end(struct packet_compteur_egress_bpf *skel,m_hook *tab_hook,int nb_itf,struct ifaddrs *list_interface){
    destroy_tab_hook_tc(tab_hook,nb_itf);
    freeifaddrs(list_interface);
    cleanup_error_early(skel);
    exit(errno);
}





int main(int argc, char const *argv[])
{
    

    signal(SIGINT,signaltrap);
    libbpf_set_print(NULL);
    float freq;

    if (argc != 2){printf("Erreur : %s <frequence> ",argv[0]);return 1;}



    if ((freq=atof(argv[1]))==0){
        printf("La fréquence d'affichage des données doit être un entier non nul\n");
        return -1;
    }

    struct ifaddrs *list_interface;
    if (getifaddrs(&list_interface) < 0) { printf(" Erreur: impossible de récupérer la liste des interfaces réseau du système\n");return -14;}
    int nb_itf = nb_interface(list_interface);


    struct packet_compteur_egress_bpf *skel;
    skel = packet_compteur_egress_bpf__open();


    if(!skel){
        printf("Impossible d'ouvrir le programme\n");
        return -44;
    }


    if (bpf_map__set_max_entries(skel->maps.my_octets,nb_itf) <0 || bpf_map__set_max_entries(skel->maps.timeexec,nb_itf) <0){
        printf("impossible de modifier le nombre d'éléments des maps \n");
        packet_compteur_egress_bpf__destroy(skel);
        return 78;
    }


    if( packet_compteur_egress_bpf__load(skel) < 0){
        printf("impossible de charger le programme dans le kernel\n"); 
        packet_compteur_egress_bpf__destroy(skel);
        return 7;
        
    }

    int fd = bpf_program__fd(skel->progs.tc_test);
    if (!fd){
        printf("impossible de récupérer l'id du programme\n");
        cleanup_error_early(skel);
    }

    m_hook tab_hook[nb_itf];int r;
    if( (r=create_tab_hook_tc(fd,nb_itf,tab_hook,list_interface)) != -1){
        printf("Erreur lors de la création des hooks\n");
        cleanup_end(skel,tab_hook,r,list_interface);
    }


    int cur_key;
    long long value;
    long long time;


    while(true){

        if(fin==1){
            printf("Arrêt du programme\n");
            cleanup_end(skel,tab_hook,nb_itf,list_interface);
        }

        cur_key = 0;
        for( struct ifaddrs *itf = list_interface; cur_key<nb_itf; itf = itf->ifa_next){
        

            if( bpf_map__lookup_elem(skel->maps.my_octets,&cur_key,sizeof(int),&value,sizeof(long long),BPF_ANY) < 0 ){ printf("Erreur lors de la lecture de la map\n");cleanup_end(skel,tab_hook,nb_itf,list_interface);}
            if( bpf_map__lookup_elem(skel->maps.timeexec,&cur_key,sizeof(int),&time,sizeof(long long),BPF_ANY) < 0 ) { printf("Erreur lors de la lecture de la map\n");cleanup_end(skel,tab_hook,nb_itf,list_interface);}
            printf("interface : %s , nombre octets : %lld , time = %lld\n",itf->ifa_name,value,time);
            cur_key++;

        }
        printf("\n");
        sleep(freq);
    }

    


}
