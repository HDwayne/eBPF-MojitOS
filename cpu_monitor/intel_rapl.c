#include "intel_rapl.skel.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> 
#include <sys/resource.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/bpf.h>


int main(int argc, char const *argv[])
{

    struct intel_rapl_bpf *skel;
    skel = intel_rapl_bpf__open_and_load();
    intel_rapl_bpf__attach(skel);

    while(true){
        ;
    }


    intel_rapl_bpf__detach(skel);
    intel_rapl_bpf__destroy(skel);

    
    return 0;
}
