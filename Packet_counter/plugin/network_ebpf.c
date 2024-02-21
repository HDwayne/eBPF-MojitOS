/*******************************************************
 Copyright (C) 2018-2023 Georges Da Costa <georges.da-costa@irit.fr>

    This file is part of Mojitos.

    Mojitos is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Mojitos is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MojitO/S.  If not, see <https://www.gnu.org/licenses/>.

 *******************************************************/



#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
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
#include "network_ebpf_ingress.skel.h"
#include "network_ebpf_egress.skel.h"
#include "network_ebpf.h"

#define NB_MAX_DEV 8
#define NB_SENSOR 6

char *_labels_network[NB_SENSOR] = {
    "%s:rxp",
    "%s:txp",
    "%s:rxb",
    "%s:txb",
    "%s:t_ingress",
    "%s:t_egress",
};

struct monitoring_hook{
    struct bpf_tc_hook ingress;
    struct bpf_tc_hook egress;
};

typedef struct monitoring_hook monitoring_hook;

struct Network {
    uint64_t values[NB_MAX_DEV][NB_SENSOR];
    struct network_ebpf_ingress_bpf *skel_ingress;
    struct network_ebpf_egress_bpf *skel_egress;
    monitoring_hook tab_hook[NB_MAX_DEV];
    char labels[NB_MAX_DEV][NB_SENSOR][128];
    char devs[NB_MAX_DEV][128];
    int ndev;
};

typedef struct Network Network;


/* créer un hook */
int create_hook_tc(monitoring_hook *tab_hook,int i,int flow,int index,int fd){
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


/* retourne le nombre d'interfaces valide */
int nb_interface (struct ifaddrs *i){

    int nb = 0;
   
    for(struct ifaddrs *t = i;t!=NULL && nb < NB_MAX_DEV;t = t->ifa_next){

        if(if_nametoindex(t->ifa_name)<= nb){
            return nb;
        }
        nb++;
    }
    return nb;
}

/* initialiser les interfaces et les hooks */
unsigned int init_network(char *dev, void **ptr)
{


    if(dev==NULL){
        exit(1);
    }

    struct Network *state = malloc(sizeof(struct Network));
    memset(state, '\0', sizeof(*state));

    state->skel_ingress = network_ebpf_ingress_bpf__open();
    state->skel_egress = network_ebpf_egress_bpf__open();

    if(!(state->skel_ingress && state->skel_egress)){
        printf("Impossible d'ouvrir le programme\n");
        return -44;
    }

    if(strcmp(dev,"X")==0){

        struct ifaddrs *list_interface;
        if (getifaddrs(&list_interface) < 0) { printf(" Erreur: impossible de récupérer la liste des interfaces réseau du système\n");return -14;}
        state->ndev = nb_interface(list_interface);

        printf("%d\n",state->ndev);

        
        int i=0;
        for(struct ifaddrs *itf = list_interface  ; i < state->ndev ; itf = itf->ifa_next,i++){

            memcpy(&(state->devs[i]), itf->ifa_name, strlen(itf->ifa_name) + 1);

            for(int j=0;j<NB_SENSOR;j++){
                snprintf(state->labels[i][j], sizeof(state->labels[i][j]), _labels_network[j], state->devs[i]);
            }
        }

        printf("%d\n",state->ndev);

    

        if (bpf_map__set_max_entries(state->skel_ingress->maps.my_data_ingress,state->ndev) <0 || bpf_map__set_max_entries(state->skel_egress->maps.my_data_egress,state->ndev) <0 ){
            printf("impossible de modifier le nombre d'éléments des maps \n");
            free(list_interface);
            network_ebpf_ingress_bpf__destroy(state->skel_ingress);
            network_ebpf_egress_bpf__destroy(state->skel_egress);
            return 78;
        }

        free(list_interface);


    }else{

        state->ndev=1;
        memcpy(&(state->devs[0]), dev, strlen(dev) + 1);
        for(int i=0;i<NB_SENSOR;i++){
            snprintf(state->labels[0][i], sizeof(state->labels[0][i]), _labels_network[i], state->devs[0]);
        }

    }


    if( network_ebpf_ingress_bpf__load(state->skel_ingress) < 0 || network_ebpf_egress_bpf__load(state->skel_egress) < 0){
        printf("impossible de charger le programme dans le kernel\n"); 
        network_ebpf_ingress_bpf__destroy(state->skel_ingress);
        network_ebpf_egress_bpf__destroy(state->skel_egress);
        return 7;
        
    }

    int fd_ingress = bpf_program__fd(state->skel_ingress->progs.tc_test_ingress);
    int fd_egress = bpf_program__fd(state->skel_egress->progs.tc_test_egress);
    if (!(fd_ingress && fd_egress) ){
        printf("impossible de récupérer l'id du programme\n");
        network_ebpf_ingress_bpf__detach(state->skel_ingress);
        network_ebpf_egress_bpf__detach(state->skel_egress);
        network_ebpf_ingress_bpf__destroy(state->skel_ingress);
        network_ebpf_egress_bpf__destroy(state->skel_egress);
        return -2;
        
    }


    int index;
    for(int i=0; i<state->ndev; i++){
        index = if_nametoindex(state->devs[i]);
        if (create_hook_tc(state->tab_hook,i,BPF_TC_INGRESS,index,fd_ingress) <0 || create_hook_tc(state->tab_hook,i,BPF_TC_EGRESS,index,fd_egress) <0 ){
            return -1;
        }

    }


    *ptr = (void *) state;



    return state->ndev * NB_SENSOR;;
}


/* libère les ressources */
void clean_network(void *ptr)
{
  Network *state = ( Network *)ptr;


  if (state == NULL) {
        return;
   }

  printf("%d\n",state->ndev);
  for(int i=0; i<state->ndev;i++ ){

        LIBBPF_OPTS(bpf_tc_opts, opts);
        opts.prog_fd = opts.prog_id = 0;
        bpf_tc_detach(&(state->tab_hook[i].ingress),&opts);
        bpf_tc_detach(&(state->tab_hook[i].egress),&opts);
        bpf_tc_hook_destroy(&(state->tab_hook[i].ingress));
        bpf_tc_hook_destroy(&(state->tab_hook[i].egress));

       
    }
    network_ebpf_ingress_bpf__detach(state->skel_ingress);
    network_ebpf_egress_bpf__detach(state->skel_egress);
    network_ebpf_ingress_bpf__destroy(state->skel_ingress);
    network_ebpf_egress_bpf__destroy(state->skel_egress);


    free(state);

}



/* pour récupérer les valeurs pour chaque interface*/
unsigned int get_network(uint64_t *results, void *ptr)
{
    Network *state = ( Network *)ptr;

    cpt_pckt res_ingress,res_egress;

    for (int i = 0; i < state->ndev; i++) {


        if (bpf_map__lookup_elem(state->skel_ingress->maps.my_data_ingress,&i,sizeof(int),&res_ingress,sizeof(cpt_pckt),BPF_ANY) <0 || bpf_map__lookup_elem(state->skel_egress->maps.my_data_egress,&i,sizeof(int),&res_egress,sizeof(cpt_pckt),BPF_ANY) <0 ){
            printf("merde\n");
            return state->ndev * NB_SENSOR;
        }

        

        for (int j = 0; j < NB_SENSOR-3; j++) {
            results[i*NB_SENSOR + 2*j] = res_ingress.data[j];
            results[i*NB_SENSOR + 2*j + 1] = res_egress.data[j];
        }


    }

    return state->ndev * NB_SENSOR;
}


/* pour afficher les labels */
void label_network(char **labels, void *ptr)
{
    struct Network *state = (struct Network *) ptr;

    for (int i = 0; i < state->ndev; i++) {
        for (int j = 0; j < NB_SENSOR; j++) {
            labels[i*NB_SENSOR + j] = state->labels[i][j];
        }
    }
}



/*---------------------- à enlever lors de la release -----------------------------------*/
int fin=0;
// catch le signal pour terminé proprement
static void signaltrap(int sig){
    fin=1;
}




int main(int argc, char *argv[])
{
    libbpf_set_print(NULL);
    signal(SIGINT,signaltrap);
    void *ptr = NULL;

    int nb=init_network(argv[1],&ptr);

    uint64_t tab_res[nb];char **labels = (char **)malloc(nb*sizeof(char*));

    label_network(labels,ptr);

    for(int i=0;i<nb;i++){
       printf("%s ",labels[i]);
    }
    printf("\n");

    while (true)
    {
        if(fin==1){
            printf("Arrêt du programme\n");
            //free(labels);
            clean_network(ptr);
            exit(0);
        }
        get_network(tab_res,ptr);
        for(int i=0;i<nb;i++){
            printf("%ld ",tab_res[i]);
        }
        printf("\n");
        sleep(1);
    }
    
    return 0;
}
