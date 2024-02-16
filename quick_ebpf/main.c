#include "lib/ebpf_lib.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void print_map_values(int map_fd, enum bpf_map_type map_type)
{
  __u32 key = 0;
  __u32 next_key;
  __u64 value;
  switch (map_type)
  {
  case BPF_MAP_TYPE_HASH:
    printf("%-10s %-20s\n", "Key", "Value");
    printf("%-10s %-20s\n", "----------", "--------------------");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
      if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0)
      {
        printf("%-10u %-20llu\n", next_key, value);
      }
      else
      {
        fprintf(stderr, "Failed to read from the map for key %u\n", next_key);
      }
      key = next_key;
    }

    break;
  // Ajoutez d'autres cas pour différents types de map et structures de données
  default:
    fprintf(stderr, "Unsupported map type\n");
  }
}

int main(int argc, char **argv)
{
  struct bpf_object *obj;
  struct bpf_map *map;
  enum bpf_map_type map_type;
  int map_fd;

  if (ebpf_init() != 0)
  {
    fprintf(stderr, "Failed to initialize eBPF\n");
    return EXIT_FAILURE;
  }

  // TODO: change the name of the eBPF program
  if (ebpf_load_attach("blocks/disk_activity.bpf.o") != 0)
  {
    fprintf(stderr, "Failed to load and attach eBPF program\n");
    ebpf_cleanup();
    return EXIT_FAILURE;
  }

  obj = ebpf_get_bpf_object();
  if (!obj)
  {
    fprintf(stderr, "Failed to get eBPF object\n");
    ebpf_cleanup();
    return EXIT_FAILURE;
  }

  // TODO: change the name of the map
  map = bpf_object__find_map_by_name(obj, "pid_write_count");
  if (!map)
  {
    fprintf(stderr, "Failed to find the map\n");
    ebpf_cleanup();
    return EXIT_FAILURE;
  }

  map_fd = bpf_map__fd(map);
  map_type = bpf_map__type(map);

  while (1)
  {
    print_map_values(map_fd, map_type);
    sleep(1);
  }

  ebpf_cleanup();
  return EXIT_SUCCESS;
}
