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
#include "plugin_ebpf.h"
#include "../src_ebpf/plugin_ebpf.skel.h"

#define NB_DATA 6
#define NB_SENSOR 2

char *_labels_plugin_ebpf[NB_SENSOR] = {
    "%s:rxp",
    "%s:txp",
};

struct Plugin {
    uint64_t values[NB_DATA];
    uint64_t tmp_values[NB_DATA];
    struct plugin_ebpf *skel;
    char labels[NB_DATA][128];
    int error;
    int ndev;
};

typedef struct Plugin Plugin;


unsigned int init_plugin_ebpf(char *dev, void **ptr)
{

    if(dev==NULL){
        exit(1);
    }

    struct Plugin *state = malloc(sizeof(struct Plugin));
    memset(state, '\0', sizeof(*state));

    state->skel = plugin_ebpf_bpf__open();

    if(!(state->skel)){
        printf("Impossible d'ouvrir le programme\n");
        state->error=ERROR_OPEN_PROG;
        exit(ERROR_OPEN_PROG);
    }


    if( plugin_ebpf_bpf__load(state->skel) < 0 ){
        printf("impossible de charger le programme dans le kernel\n");
        state->error=ERROR_LOAD_PROG;
        exit(ERROR_LOAD_PROG);
        
    }

    *ptr = (void *) state;



    return state->ndev * NB_SENSOR;
    
}




/* récupère les données */
unsigned int get_plugin_ebpf(uint64_t *results, void *ptr)
{
    Plugin *state = ( Plugin *)ptr;

    int val;


    for (int i = 0; i < NB_DATA; i++) {

        if (bpf_map__lookup_elem(state->skel,&i,sizeof(int),&val,sizeof(int),BPF_ANY) <0){
            printf("Erreur : impossible de lire les informations contenus dans les maps \n");
            return ERROR_ACCESS_ELEM;
        }


        results[i] = state->tmp_values[i];
        
        state->tmp_values[i] = val; 

    }

    return NB_DATA;
}

void clean_plugin_ebpf(void *){
    Plugin *state = ( Plugin *)ptr;

    if (state == NULL) {
        return;
    }

    if ( state ->error < -1 || state->error == 0 ){

        if ( state->error < -3 || state->error == 0 ){

            plugin_ebpf__bpf__detach(state->skel);
        }

        plugin_ebpf__bpf__destroy(state->skel);
    }
    free(state->skel);
    free(state);
}


void label_plugin_ebpf(char **labels, void *ptr)
{
    struct Plugin *state = (struct Plugin *) ptr;

    for (int i = 0; i < state->ndev; i++) {
        labels[i] = state->labels[i
    }
}
