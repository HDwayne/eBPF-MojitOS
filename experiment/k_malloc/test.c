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

int main(void)
{
    signal(SIGINT, signaltrap);


    struct test_bpf *skel = test_bpf__open();
    test_bpf__load(skel);
    test_bpf__attach(skel);


    int key = 0;
    int value;


	while(true){

        if (fin)
            break;

		sleep(2);

        bpf_map__lookup_elem(skel->maps.perf_map, &key, sizeof(int), &value, sizeof(int), BPF_ANY);
        printf("kmalloc: %d\n", value);
	}

    //On détache le programme bpf
    test_bpf__detach(skel);
    test_bpf__destroy(skel);

    return 0;
}