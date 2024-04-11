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

/*here, you just have to modify every word "plugin" by your word"*/

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
//#include "plugin_ebpf.h"
#include "cpu_frequency.skel.h"

#define ERROR_OPEN_PROG -1
#define ERROR_LOAD_PROG -2
#define ERROR_ATTACH_PROG -3
#define ERROR_ACCESS_ELEM -4

#define NB_SENSOR 32
#define NB_DATA 16

char *_labels_cpu_frequency_ebpf[NB_SENSOR] = {
    "%s:cpu0",
    "%s:cpu0",
    "%s:cpu1",
    "%s:cpu1",
    "%s:cpu2",
    "%s:cpu2",
    "%s:cpu3",
    "%s:cpu3",
    "%s:cpu4",
    "%s:cpu4",
    "%s:cpu5",
    "%s:cpu5",
    "%s:cpu6",
    "%s:cpu6",
    "%s:cpu7",
    "%s:cpu7",
    "%s:cpu8",
    "%s:cpu8",
    "%s:cpu9",
    "%s:cpu9",
    "%s:cpu10",
    "%s:cpu10",
    "%s:cpu11",
    "%s:cpu11",
    "%s:cpu12",
    "%s:cpu12",
    "%s:cpu13",
    "%s:cpu13",
    "%s:cpu14",
    "%s:cpu14",
    "%s:cpu15",
    "%s:cpu15",
};

struct Freq {
    uint64_t values[NB_DATA];
    struct cpu_frequency_bpf *skel;
    // time_compteur_temp[NB_DATA];
    // time_compteur[NB_DATA];
    int nb_freq_switch[NB_DATA];
    char labels[NB_SENSOR][128];
    int error;
};

typedef struct Freq Freq;





int fin = 0;
static void signaltrap(int signo)
{
    fin = 1;
}

void clean_cpu_frequency_ebpf(void *ptr);


unsigned int init_cpu_frequency_ebpf(void **ptr)
{


    struct Freq *state = malloc(sizeof(struct Freq));
    memset(state, '\0', sizeof(*state));

    state->skel = cpu_frequency_bpf__open();


    for (int i=0;i<NB_SENSOR;i+=2){
        snprintf(state->labels[i], sizeof(state->labels[i]), _labels_cpu_frequency_ebpf[i],"frequency");
        snprintf(state->labels[i+1], sizeof(state->labels[i+1]), _labels_cpu_frequency_ebpf[i+1],"switch_freq");
    }

    if(!(state->skel)){
        printf("Impossible d'ouvrir le programme\n");
        state->error=ERROR_OPEN_PROG;
        exit(ERROR_OPEN_PROG);
    }




    if( cpu_frequency_bpf__load(state->skel) < 0 ){
        printf("impossible de charger le programme dans le kernel\n");
        state->error=ERROR_LOAD_PROG;
        clean_cpu_frequency_ebpf(state);
        exit(ERROR_LOAD_PROG);
        
    }



    if (cpu_frequency_bpf__attach(state->skel) <0){
        printf("impossible d'attacher le programme \n");
        state->error=ERROR_ATTACH_PROG;
        clean_cpu_frequency_ebpf(state);
        exit(ERROR_ATTACH_PROG);
    }


    *ptr = (void *) state;



    return NB_SENSOR;
    
}




/* récupère les données */
unsigned int get_cpu_frequency_ebpf(uint64_t *results, void *ptr)
{
    Freq *state = ( Freq *)ptr;

    __u32 val;


    for (int i = 0; i < NB_DATA; i++) {

        if (bpf_map__lookup_elem(state->skel->maps.perf_map,&i,sizeof(__u32),&val,sizeof(__u32),BPF_ANY) <0){
            printf("Erreur : impossible de lire les informations contenus dans les maps \n");
            state->error=ERROR_ACCESS_ELEM;
            clean_cpu_frequency_ebpf(state);
            exit(ERROR_ACCESS_ELEM);
        }

        if (state->values[i]!=val){
            state->nb_freq_switch[i]+=1;
        }

        state->values[i]=val;


        results[i*2] = val;
        results[i*2+1] = state->nb_freq_switch[i];
    

    }

    return NB_DATA;
}

void clean_cpu_frequency_ebpf(void *ptr){
    Freq *state = ( Freq *)ptr;

    if (state == NULL) {
        return;
    }

    if ( state ->error < -1 || state->error == 0 ){



        if (state->error < -2 || state->error == 0){
            cpu_frequency_bpf__detach(state->skel);
        }

        cpu_frequency_bpf__destroy(state->skel);
    }
    free(state);
}


void label_cpu_frequency_ebpf(char **labels, void *ptr)
{
    struct Freq *state = (struct Freq *) ptr;

    for (int i = 0; i < NB_SENSOR; i++) {
        labels[i] = state->labels[i];

    }
}



//----------à elever lors de la release----------------------//

int main(int argc, char *argv[])
{
    signal(SIGINT,signaltrap);
    void *ptr = NULL;

    int nb;
    if( (nb=init_cpu_frequency_ebpf(&ptr))<0){
        return 1;
    }

    uint64_t tab_res[nb];char **labels = (char **)malloc(nb*sizeof(char*));

    label_cpu_frequency_ebpf(labels,ptr);

    for(int i=0;i<nb;i++){
       printf("%s ",labels[i]);
    }
    printf("\n");

    while (true)
    {
        if(fin==1){
            printf("Arrêt du programme\n");

            clean_cpu_frequency_ebpf(ptr);
            exit(0);
        }
        if(get_cpu_frequency_ebpf(tab_res,ptr)<0){
            return 2;
        }
        for(int i=0;i<nb;i++){
            printf("%ld ",tab_res[i]);
        }
        printf("\n");
        sleep(1);
    }
    
    return 0;
}
