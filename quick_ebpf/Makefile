CC=clang
CFLAGS=-I. -Wall
LDFLAGS=-L/usr/lib/x86_64-linux-gnu -lbpf
BPFTOOL=bpftool

# Chemin vers les programmes eBPF
EBPF_PROGRAMS_PATH=./ebpf_programs
BUILD_DIR := ./build

# Assurez-vous que le répertoire de build existe
$(shell mkdir -p $(BUILD_DIR))

# Trouver tous les fichiers .bpf.c dans EBPF_PROGRAMS_PATH
EBPF_SOURCES=$(wildcard $(EBPF_PROGRAMS_PATH)/*.bpf.c)
# Transformer les .bpf.c en .o (fichiers ELF BPF) dans le répertoire de build
EBPF_OBJECTS=$(patsubst $(EBPF_PROGRAMS_PATH)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(EBPF_SOURCES))
# Transformer les .bpf.c en .skel.h dans le répertoire de build
EBPF_HEADERS=$(patsubst $(EBPF_PROGRAMS_PATH)/%.bpf.c,$(BUILD_DIR)/%.bpf.skel.h,$(EBPF_SOURCES))


# Fichier généré contenant les #include et la structure ebpf_programs
AUTOGEN_HEADER=$(BUILD_DIR)/ebpf_programs_autogen.h

.PHONY: all clean vmlinux.h autogen

all: vmlinux.h ebpf_programs autogen main

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BUILD_DIR)/vmlinux.h

ebpf_programs: $(EBPF_HEADERS)

$(BUILD_DIR)/%.bpf.o: $(EBPF_PROGRAMS_PATH)/%.bpf.c
	$(CC) -g -O2 -target bpf -c $< -o $@

$(BUILD_DIR)/%.bpf.skel.h: $(BUILD_DIR)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

autogen: $(EBPF_HEADERS)
	@echo "// Généré automatiquement. Ne pas modifier." > $(AUTOGEN_HEADER)
	@$(foreach hdr,$(EBPF_HEADERS),echo '#include "$(subst ./,,$(hdr))"' >> $(AUTOGEN_HEADER);)
	@echo "" >> $(AUTOGEN_HEADER)
	@echo "struct bpf_program_data" >> $(AUTOGEN_HEADER)
	@echo "{" >> $(AUTOGEN_HEADER)
	@echo "    const char *name;" >> $(AUTOGEN_HEADER)
	@echo "    void *skel;" >> $(AUTOGEN_HEADER)
	@echo "    void (*skeleton_destroy)(void *);" >> $(AUTOGEN_HEADER)
	@echo "    void *(*skeleton_open_and_load)(void);" >> $(AUTOGEN_HEADER)
	@echo "    int (*skeleton_attach)(void *);" >> $(AUTOGEN_HEADER)
	@echo "};" >> $(AUTOGEN_HEADER)
	@echo "" >> $(AUTOGEN_HEADER)
	@echo "static struct bpf_program_data ebpf_programs[] = {" >> $(AUTOGEN_HEADER)
	@$(foreach hdr,$(EBPF_HEADERS), \
		echo "    {" >> $(AUTOGEN_HEADER); \
		name=`echo "$(notdir $(hdr))" | sed 's/\.bpf\.skel\.h//g'`; \
		echo "        .name = \"$$name\"," >> $(AUTOGEN_HEADER); \
		echo "        .skeleton_open_and_load = (void *(*)(void))$$name""_bpf__open_and_load," >> $(AUTOGEN_HEADER); \
		echo "        .skeleton_attach = (int (*)(void *))$$name""_bpf__attach," >> $(AUTOGEN_HEADER); \
		echo "        .skeleton_destroy = (void (*)(void *))$$name""_bpf__destroy," >> $(AUTOGEN_HEADER); \
		echo "    }," >> $(AUTOGEN_HEADER); \
	)
	@echo "};" >> $(AUTOGEN_HEADER)

main: main.c $(AUTOGEN_HEADER)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) main
