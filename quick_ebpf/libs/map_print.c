#include "map_print.h"

PRINT_KEY_VALUE_FUNCTION(uint32_t, uint32_t, "%u", "%u")
PRINT_KEY_VALUE_FUNCTION(uint64_t, uint64_t, "%lu", "%lu")
PRINT_KEY_VALUE_FUNCTION(uint32_t, uint64_t, "%u", "%lu")
PRINT_KEY_VALUE_FUNCTION(uint64_t, uint32_t, "%lu", "%u")

void print_key_value(void *key, void *value, size_t key_size, size_t value_size)
{
  if (key_size == sizeof(uint32_t) && value_size == sizeof(uint32_t))
  {
    print_key_value_uint32_t_uint32_t(key, value);
  }
  else if (key_size == sizeof(uint64_t) && value_size == sizeof(uint64_t))
  {
    print_key_value_uint64_t_uint64_t(key, value);
  }
  else if (key_size == sizeof(uint32_t) && value_size == sizeof(uint64_t))
  {
    print_key_value_uint32_t_uint64_t(key, value);
  }
  else if (key_size == sizeof(uint64_t) && value_size == sizeof(uint32_t))
  {
    print_key_value_uint64_t_uint32_t(key, value);
  }
  else
  {
    fprintf(stderr, "Unsupported key/value size combination: key=%zu, value=%zu\n", key_size, value_size);
  }
}

void handle_hash_or_array_map(int map_fd)
{
  struct bpf_map_info map_info;
  __u32 info_len = sizeof(map_info);
  if (bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len) != 0)
  {
    fprintf(stderr, "Could not get map info\n");
    return;
  }

  void *key = malloc(map_info.key_size);
  void *next_key = malloc(map_info.key_size);
  void *value = malloc(map_info.value_size);
  if (!key || !next_key || !value)
  {
    fprintf(stderr, "Failed to allocate memory\n");
    free(key);
    free(next_key);
    free(value);
    return;
  }

  memset(key, 0, map_info.key_size);

  while (bpf_map_get_next_key(map_fd, key, next_key) == 0)
  {
    if (bpf_map_lookup_elem(map_fd, next_key, value) == 0)
    {
      print_key_value(next_key, value, map_info.key_size, map_info.value_size);
    }
    memcpy(key, next_key, map_info.key_size);
  }

  free(key);
  free(next_key);
  free(value);
}

void handle_prog_array_map(int map_fd)
{
  printf("Handling program array map\n");
}

void handle_perf_event_array_map(int map_fd)
{
  printf("Handling perf event array map\n");
}

void handle_stack_trace_map(int map_fd)
{
  printf("Handling stack trace map\n");
}

void handle_cgroup_array_map(int map_fd)
{
  printf("Handling cgroup array map\n");
}

void print_map_info(int map_fd)
{
  struct bpf_map_info info = {};
  __u32 info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len))
  {
    perror("Could not get map info");
    return;
  }

  printf("Map type: %d\n", info.type);

  switch (info.type)
  {
  case BPF_MAP_TYPE_HASH:
  case BPF_MAP_TYPE_ARRAY:
  case BPF_MAP_TYPE_PERCPU_HASH:
  case BPF_MAP_TYPE_PERCPU_ARRAY:
  case BPF_MAP_TYPE_LRU_HASH:
  case BPF_MAP_TYPE_LRU_PERCPU_HASH:
    handle_hash_or_array_map(map_fd);
    break;
  case BPF_MAP_TYPE_PROG_ARRAY:
    handle_prog_array_map(map_fd);
    break;
  case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
    handle_perf_event_array_map(map_fd);
    break;
  case BPF_MAP_TYPE_STACK_TRACE:
    handle_stack_trace_map(map_fd);
    break;
  case BPF_MAP_TYPE_CGROUP_ARRAY:
    handle_cgroup_array_map(map_fd);
    break;
  default:
    printf("Unsupported map type\n");
    break;
  }
}