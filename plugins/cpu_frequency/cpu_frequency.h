
unsigned int init_cpu_frequency_ebpf( void **ptr);
unsigned int get_cpu_frequency_ebpf(uint64_t *results, void *ptr);
void label_cpu_frequency_ebpf(char **labels, void *ptr);
void clean_cpu_frequency_ebpf(void *ptr);

/*Sensor cpu_frequency = {
    .init = init_cpu_frequency_ebpf,
    .get = get_cpu_frequency_ebpf,
    .clean = clean_cpu_frequency_ebpf,
    .label = label_cpu_frequency,
    .nb_opt = 1,
};

Optparse cpu_frequency_opt[1] = {
    {
        .longname = "cpu_frequency_ebpf",
        .shortname = 'F',
        .argtype = OPTPARSE_REQUIRED,
        .usage_arg = ""
        .usage_msg = "cpu_frequency with eBPF",
    }
};*/