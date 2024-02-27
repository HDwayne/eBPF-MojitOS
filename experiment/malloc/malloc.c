#include <stdio.h>
#include <unistd.h>
#include "malloc.skel.h"


struct kmalloc_value{
    unsigned long value;
    unsigned long tmp_value;
};


int fin=0;
// catch le signal pour terminé proprement
static void signaltrap(int sig){
    fin=1;

}



int main(int argc, char const *argv[])
{
    struct malloc_bpf *skel = malloc_bpf__open();
    if (!skel){
        return -1;
    }

    if(malloc_bpf__load(skel)<0){
        return -2;
    }

    struct kmalloc_value val;int key=0;
    val.tmp_value=0;
    while(true){


        if(fin){
            malloc_bpf__detach(skel);
            malloc_bpf__destroy(skel);
            break;
        }

        if(bpf_map__lookup_elem(skel->maps.data_vmalloc,&key,sizeof(int),&(val.value),sizeof(unsigned long),BPF_ANY) <0){
            printf("probleme\n");
        }
        printf("nb octets alloués : %ld\n",val.value-val.tmp_value);
        val.tmp_value=val.value;
        sleep(1);

    }
    return 0;
}

