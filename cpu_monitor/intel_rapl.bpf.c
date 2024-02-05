#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>



SEC("tracepoint/thermal/thermal_temperature")
int tp_test(struct trace_event_raw_thermal_temperature *ctx) {

    bpf_printk("%d\n",ctx->temp);
    return 0;
    	
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
    	
	
