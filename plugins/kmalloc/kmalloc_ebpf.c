#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "test.skel.h"
#include <linux/bpf.h>
#include <signal.h>

//Capture du signal pour arrêter le programme
int fin = 0;
static void signaltrap(int signo)
{
    printf("Signal %d received\n", signo);
    fin = 1;
}



unsigned int init_kmalloc_ebpf(char *, void **){



}
unsigned int get_kmalloc_ebpf(uint64_t *results, void *){





}
void clean_kmalloc_ebpf(void *){





}
void label_kmalloc_ebpf(char **labels, void *){





    
}




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