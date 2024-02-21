BIN_ingress="network_ebpf_ingress"
BIN_egress ="network_ebpf_egress"
USER_BIN = "network_ebpf"

all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_ARCH_x86 -c *.bpf.c 
	@bpftool gen skeleton $(BIN_ingress).bpf.o > $(BIN_ingress).skel.h
	@bpftool gen skeleton $(BIN_egress).bpf.o > $(BIN_egress).skel.h
	@clang $(USER_BIN).c -lbpf -lelf -o $(USER_BIN)

.PHONY: clean
clean:
	@rm -rf *.o *.skel.h vmlinux.h $(USER_BIN)
