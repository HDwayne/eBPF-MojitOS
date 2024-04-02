#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "brk.skel.h"
#include <linux/bpf.h>
#include <signal.h>

//Capture du signal pour arrêter le programme
int fin = 0;
static void signaltrap(int signo)
{
    printf("Signal %d received\n", signo);
    fin = 1;
}

int main(void)
{
    signal(SIGINT, signaltrap);


    struct brk_bpf *skel = brk_bpf__open();
    brk_bpf__load(skel);
    brk_bpf__attach(skel);


    int key = 0;
    unsigned long value;


	while(true){

        if (fin)
            break;

		sleep(2);

        bpf_map__lookup_elem(skel->maps.perf_map, &key, sizeof(int), &value, sizeof(unsigned long), BPF_ANY);
        printf("brk: %lu\n", value);
	}

    //On détache le programme bpf
    brk_bpf__detach(skel);
    brk_bpf__destroy(skel);

    return 0;
}