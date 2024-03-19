#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include "util.h"
#include "kmalloc_ebpf.skel.h"


#define NB_DATA 6

struct Kmalloc {
    uint64_t values[NB_DATA];
    uint64_t tmp_values[NB_DATA];
    struct kmalloc_ebpf_bpf *skel;
    char labels[NB_DATA][128];
    char devs[NB_DATA][128];
    int error;
    int ndata;
};

typedef struct Kmalloc Kmalloc;

//Capture du signal pour arrêter le programme ( à enlever )
int fin = 0;
static void signaltrap(int signo)
{
    printf("Signal %d received\n", signo);
    fin = 1;
}



unsigned int init_kmalloc_ebpf(char *, void **){


    //TODO

}
unsigned int get_kmalloc_ebpf(uint64_t *results, void *){

    //TODO

    Kmalloc *state = ( Kmalloc *)ptr;

    uint64_t bytes_req,bytes_alloc;


    if (bpf_map__lookup_elem(state->skel,&i,sizeof(int),&bytes_req,sizeof(uint64_t),BPF_ANY) <0 || bpf_map__lookup_elem(state->skel,&i,sizeof(int),&bytes_alloc,sizeof(uint64_t),BPF_ANY)){
        printf("Erreur : impossible de lire les informations contenus dans les maps \n");
        return ERROR_ACCESS_ELEM;
    }


  
    results[0] = 
    results[1] = 

    state->tmp_values[0]= 
    state->tmp_values[1] = 

    


    

    return NB_DATA;




}

void clean_kmalloc_ebpf(void *){


    Kmalloc *state = ( Kmalloc *)ptr;


    if (state == NULL) {
        return;
    }


    if ( state ->error < -1 || state->error == 0 ){

        if ( state->error < -3 || state->error == 0 ){

            network_ebpf_ingress_bpf__detach(state->skel);
        }

        network_ebpf_ingress_bpf__destroy(state->skel);
    }

    free(state->skel);
    free(state);



}

void label_kmalloc_ebpf(char **labels, void *){


    struct Kmalloc *state = (struct Kmalloc *) ptr;

    for (int i = 0; i < state->ndata; i++) {
        labels[i] = state->labels[i];
    }
}



//----------à elever lors de la release----------------------//


int main(void)
{
    signal(SIGINT, signaltrap);


    struct test_bpf *skel = test_bpf__open();
    test_bpf__load(skel);
    test_bpf__attach(skel);

	while(true){

        if (fin)
            break;
	}

    //On détache le programme bpf
    test_bpf__detach(skel);
    test_bpf__destroy(skel);

    return 0;
}