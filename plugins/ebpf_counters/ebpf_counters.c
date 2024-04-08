#include "ebpf_option.h"
#include <fcntl.h>
#include <info_reader.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 

inclure les fichiers skel.h de tous les counters

*/
typedef struct{

    void init;
    void get;
    void clean;
    void label;
    char * name;

} EbpfProg;

typedef struct {
    EbpfProg *keys;
    unsigned int count;
    
} EbpfCounters;




EbpfProg *build_keyfinder(unsigned int count, unsigned int *indexes)
{
    EbpfProg *keys = (EbpfProg *)calloc(count, sizeof(EbpfProg));
    for (unsigned int i = 0; i < count; i++) {
        unsigned int idx = indexes[i];
        EbpfProg key = { .init =
                         .get =
                         .clean =
                         .name = ebpf_counters[i];

        };
        memcpy(&keys[i], &key, sizeof(EbpfProg));
    }
    return keys;
}




void ebpf_list(char *ebpf_string, unsigned int *count,
                 unsigned int *indexes)
{
    char *token;
    *count = 0;

    while ((token = strtok(ebpf_string, ",")) != NULL) {
        ebpf_string = NULL;

        unsigned int i;
        for (i = 0; i < NB_COUNTERS; i++) {
            if (strcmp(ebpf_counters[i], token) == 0) {
                (*count)++;
                indexes[*count - 1] = i;
                break;
            }
        }

        if (i == NB_COUNTERS) {
            fprintf(stderr, "Unknown ebpf counter: %s\n", token);
            exit(EXIT_FAILURE);
        }

        if ((*count) > NB_COUNTERS) {
            fprintf(stderr, "Too much counters, there are probably duplicates\n");
            exit(EXIT_FAILURE);
        }
    }
}



unsigned int init_ebpf_counters(char *args, void **ptr)
{
    unsigned int indexes[NB_COUNTERS];
    unsigned int count = 0;
    memory_list(args, &count, indexes);



    EbpfProg *keys = build_keyfinder(count, indexes);

    EbpfCounters *counters = calloc(1, sizeof(EbpfCounters));
    counters -> keys = keys;
    counters -> count = count;
   

    *ptr = (void *)counters;
    return count;
}

unsigned int get_memory_counters(uint64_t *results, void *ptr)
{
    EbpfCounters *counters = (EbpfCounters *)ptr;


    return counters->count;
}

void label_memory_counters(char **labels, void *ptr)
{
    EbpfCounters *counters = (EbpfCounters *)ptr;
    for (unsigned int i = 0; i < counters->count; i++) {
        labels[i] = counters->keys[i].name;
    }
}

void clean_memory_counters(void *ptr)
{
    EbpfCounters *counters = (EbpfCounters *)ptr;

    free(counters->keys);
    free(ptr);
}

void *show_all_ebpf_counters(void *none1, size_t none2)
{
    for (unsigned int i = 0; i < NB_COUNTERS; i++) {
        printf("%s\n", ebpf_counters[i]);
    }

    UNUSED(none1);
    UNUSED(none2);
    exit(EXIT_SUCCESS);
    return NULL; /* not reached */
}
