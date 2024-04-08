#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include "util.h"
#include "kmalloc_ebpf.skel.h"

#define NB_SENSOR 2


#define ERROR_OPEN_PROG -1
#define ERROR_LOAD_PROG -2
#define ERROR_ACCESS_ELEM -3


char *_labels_kmalloc_ebpf[NB_SENSOR] = {
    "%s:bytes_req",
    "%s:bytes_alloc",
};

struct Kmalloc {
    uint64_t values[NB_SENSOR];
    uint64_t tmp_values[NB_SENSOR];
    struct kmalloc_ebpf_bpf *skel;
    char labels[NB_SENSOR][128];
    int error;
    int ndata;
};

typedef struct Kmalloc Kmalloc;

//Capture du signal pour arrêter le programme ( à enlever )
int fin = 0;
static void signaltrap(int signo)
{
    fin = 1;
}

void clean_kmalloc_ebpf(void *ptr);


unsigned int init_kmalloc_ebpf(char *dev , void **ptr){


    if(dev==NULL){
        exit(1);
    }

    struct Kmalloc*state = malloc(sizeof(struct Kmalloc));
    memset(state, '\0', sizeof(*state));

    state->skel = kmalloc_ebpf_bpf__open();

    if(!(state->skel)){
        printf("Impossible d'ouvrir le programme\n");
        state->error=ERROR_OPEN_PROG;
        exit(ERROR_OPEN_PROG);
    }


    if( kmalloc_ebpf_bpf__load(state->skel) < 0 ){
        printf("impossible de charger le programme dans le kernel\n");
        state->error=ERROR_LOAD_PROG;
        clean_kmalloc_ebpf(state);
        exit(ERROR_LOAD_PROG);
        
    }

    state->ndata=NB_SENSOR;

    *ptr = (void *) state;



    return NB_SENSOR;
}

unsigned int get_kmalloc_ebpf(uint64_t *results, void *ptr){


    Kmalloc *state = ( Kmalloc *)ptr;

    uint64_t bytes;



    for(int i=0;i<state->ndata;i++){
        if (bpf_map__lookup_elem(state->skel->maps.data_kmalloc,&i,sizeof(int),&bytes,sizeof(uint64_t),BPF_ANY) <0){
            printf("Erreur : impossible de lire les informations contenus dans les maps \n");
            state->error= ERROR_ACCESS_ELEM;
            clean_kmalloc_ebpf(state);
            exit(ERROR_ACCESS_ELEM);
        }

  
        results[i] = modulo_substraction(bytes,state->tmp_values[i]);
        //results[i]= bytes;

        state->tmp_values[i]= bytes;

    }

    

    return state->ndata;
}

void clean_kmalloc_ebpf(void *ptr){


    Kmalloc *state = ( Kmalloc *)ptr;


    if (state == NULL) {
        return;
    }


    if ( state ->error < -1 || state->error == 0 ){

        if ( state->error == -3 || state->error == 0 ){

            kmalloc_ebpf_bpf__detach(state->skel);
        }

        kmalloc_ebpf_bpf__destroy(state->skel);
    }

    free(state);



}

void label_kmalloc_ebpf(char **labels, void *ptr){


    struct Kmalloc *state = (struct Kmalloc *) ptr;

    for (int i = 0; i < state->ndata; i++) {
        labels[i] = state->labels[i];
    }
}



//----------à elever lors de la release----------------------//

int main(int argc, char *argv[])
{
    signal(SIGINT,signaltrap);
    void *ptr = NULL;

    int nb;
    if( (nb=init_kmalloc_ebpf(argv[1],&ptr))<0){
        return 1;
    }

    uint64_t tab_res[nb];char **labels = (char **)malloc(nb*sizeof(char*));

    label_kmalloc_ebpf(labels,ptr);

    for(int i=0;i<nb;i++){
       printf("%s ",labels[i]);
    }
    printf("\n");

    while (true)
    {
        if(fin==1){
            printf("Arrêt du programme\n");

            clean_kmalloc_ebpf(ptr);
            exit(0);
        }
        if(get_kmalloc_ebpf(tab_res,ptr)<0){
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