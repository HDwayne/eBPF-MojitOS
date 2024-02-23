USER_BIN = ebpf_app
LIBS = -lbpf -lelf
CC = clang
BPF_CLANG = clang
BPF_CFLAGS = -g -O2 -c -target bpf
BPF_LDFLAGS =
BPF_SRC = $(wildcard ebpf_programs/*.bpf.c)
BPF_OBJ = $(patsubst %.bpf.c,%.bpf.o,$(BPF_SRC))

# Rule to compile BPF programs
%.bpf.o: %.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $< -o $@

all: vmlinux.h $(USER_BIN) $(BPF_OBJ)

$(USER_BIN): main.c lib/ebpf_lib.c
	$(CC) -I./lib -o $@ $^ $(LIBS)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(USER_BIN) $(BPF_OBJ) lib/*.o vmlinux.h

.PHONY: all clean
