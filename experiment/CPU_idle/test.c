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


    __u32 key;
    __u64 value;


	while(true){

        if (fin)
            break;

		sleep(10);

        //On parcourt les 5 premiere clé de la map pour afficher les valeurs
        for (key=0; key<5; key++){
            //On récupère la valeur de la map
            bpf_map__lookup_elem(skel->maps.perf_map, &key, sizeof(__u32), &value, sizeof(__u64), BPF_ANY);
            printf("CPU %d: %lld\n", key, value);
        }
	}

    //On détache le programme bpf
    test_bpf__detach(skel);
    test_bpf__destroy(skel);

    return 0;
}