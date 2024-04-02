BIN="kmalloc_ebpf"

all:
	@gcc -Wall -O3 -Werror -c util.c -o util.o
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_ARCH_x86 -c $(BIN).bpf.c -o $(BIN).bpf.o
	@bpftool gen skeleton $(BIN).bpf.o > $(BIN).skel.h
	@clang -O3 -g -c $(BIN).c -o $(BIN).o
	@clang -lbpf -lelf -o $(BIN) util.o $(BIN).o




.PHONY: clean
clean:
	@rm -rf *.o *.skel.h vmlinux.h $(BIN)
