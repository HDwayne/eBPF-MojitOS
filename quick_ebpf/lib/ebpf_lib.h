#ifndef EBPF_LIB_H
#define EBPF_LIB_H

struct bpf_object *ebpf_get_bpf_object(void);
int ebpf_init(void);
int ebpf_load_attach(const char *filename);
void ebpf_cleanup(void);

#endif
