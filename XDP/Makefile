BIN="packet_compteur"

all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_ARCH_x86 -c $(BIN).bpf.c -o $(BIN).bpf.o

.PHONY: clean
clean:
	@rm -rf *.o *.skel.h vmlinux.h $(USER_BIN)
