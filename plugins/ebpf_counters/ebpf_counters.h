unsigned int init_ebpf_counters(char *args, void **ptr);
unsigned int get_ebpf_counters(uint64_t *results, void *ptr);
void label_ebpf_counters(char **labels, void *ptr);
void clean_ebpf_counters(void *ptr);
void *show_all_ebpf_counters(void *, size_t);

/*Sensor ebpf_counters = {
    .init = init_ebpf_counters,
    .get = get_ebpf_counters,
    .clean = clean_ebpf_counters,
    .label = label_ebpf_counters,
    .nb_opt = 2,
};

Optparse ebpf_counters_opt[2] = {
    {
        .longname = "ebpf-counters",
        .shortname = 'E',
        .argtype = OPTPARSE_REQUIRED,
        .usage_arg = "<ebpf_list>",
        .usage_msg =
        "ebpf counters\n"
        "\tebpf_list is a coma separated list of ebpf counters.\n"
        "\tEx: Zswap,Zswapped",
    },
    {
        .longname = "ebpf-list",
        .shortname = 'T',
        .argtype = OPTPARSE_NONE,
        .usage_arg = NULL,
        .usage_msg = "list the available ebpf counters and quit",
        .fn = show_all_ebpf_counters,
    },
};*/
