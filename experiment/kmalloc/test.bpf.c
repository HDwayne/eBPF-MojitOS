#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct s_mystruct
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    unsigned long call_site;
    const void *ptr;
    size_t bytes_req;
    size_t bytes_alloc;
    unsigned long gfp_flags;
    int node;
};

SEC("tracepoint/kmem/kmalloc")
void kmalloc(struct s_mystruct *ctx)
{

    bpf_printk("kmalloc: call_site : %lu  | ptr %p | bytes_req : %zu | bytes allocs : %zu\n", ctx->call_site, ctx->ptr, ctx->bytes_req, ctx->bytes_alloc);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
