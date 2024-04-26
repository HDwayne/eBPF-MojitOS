#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include "mmap_ebpf.skel.h"

#define NB_SENSOR 2


#define ERROR_OPEN_PROG -1
#define ERROR_LOAD_PROG -2
#define ERROR_ACCESS_ELEM -3


char *_labels_mmap_ebpf[NB_SENSOR] = {
    "%s:bytes_len",
    "%s:compteur",
};

struct Mmap {
    unsigned long values[NB_SENSOR];
    unsigned long tmp_values[NB_SENSOR];
    struct mmap_ebpf_bpf *skel;
    char labels[NB_SENSOR][128];
    int error;
    int ndata;
};

typedef struct Mmap Mmap;

//Capture du signal pour arrêter le programme ( à enlever )
int fin = 0;
static void signaltrap(int signo)
{
    fin = 1;
}

void clean_mmap_ebpf(void *ptr);


unsigned int init_mmap_ebpf(void **ptr){

    struct Mmap* state = malloc(sizeof(struct Mmap));
    memset(state, '\0', sizeof(*state));

    state->skel = mmap_ebpf_bpf__open();
    snprintf(state->labels[0], sizeof(state->labels[0]), _labels_mmap_ebpf[0],"len");
    snprintf(state->labels[1], sizeof(state->labels[1]), _labels_mmap_ebpf[1],"compteur");
    

    if(!(state->skel)){
        printf("Impossible d'ouvrir le programme\n");
        state->error=ERROR_OPEN_PROG;
        exit(ERROR_OPEN_PROG);
    }


    if( mmap_ebpf_bpf__load(state->skel) < 0 ){
        printf("impossible de charger le programme dans le kernel\n");
        state->error=ERROR_LOAD_PROG;
        clean_mmap_ebpf(state);
        exit(ERROR_LOAD_PROG);
        
    }

    mmap_ebpf_bpf__attach(state->skel);

    state->ndata=NB_SENSOR;

    *ptr = (void *) state;



    return NB_SENSOR;
}

unsigned int get_mmap_ebpf(uint64_t *results, void *ptr){


    Mmap *state = ( Mmap *)ptr;

    unsigned long bytes;



    for(int i=0;i<state->ndata;i++){
        if (bpf_map__lookup_elem(state->skel->maps.data_mmap,&i,sizeof(int),&bytes,sizeof(unsigned long),BPF_ANY) <0){
            printf("Erreur : impossible de lire les informations contenus dans les maps \n");
            state->error= ERROR_ACCESS_ELEM;
            clean_mmap_ebpf(state);
            exit(ERROR_ACCESS_ELEM);
        }
        
        results[i] = bytes;

        state->tmp_values[i]= bytes;

    }

    

    return state->ndata;
}

void clean_mmap_ebpf(void *ptr){


    Mmap *state = ( Mmap *)ptr;


    if (state == NULL) {
        return;
    }


    if ( state ->error < -1 || state->error == 0 ){

        if ( state->error == -3 || state->error == 0 ){

            mmap_ebpf_bpf__detach(state->skel);
        }

        mmap_ebpf_bpf__destroy(state->skel);
    }
    
    free(state);



}

void label_mmap_ebpf(char **labels, void *ptr){


    struct Mmap *state = (struct Mmap *) ptr;

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
    if( (nb=init_mmap_ebpf(&ptr))<0){
        return 1;
    }

    uint64_t tab_res[nb];
    char **labels = (char **)malloc(nb*sizeof(char*));

    label_mmap_ebpf(labels,ptr);

    for(int i=0;i<nb;i++){
       printf("%s ",labels[i]);
    }
    printf("\n");

    while (true)
    {
        if(fin==1){
            printf("Arrêt du programme\n");

            clean_mmap_ebpf(ptr);
            exit(0);
        }
        if(get_mmap_ebpf(tab_res,ptr)<0){
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
