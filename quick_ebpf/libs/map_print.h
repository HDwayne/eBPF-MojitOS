#ifndef MAP_PRINT_H
#define MAP_PRINT_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <bpf/bpf.h>

#define PRINT_KEY_VALUE_FUNCTION(KEY_TYPE, VALUE_TYPE, KEY_FORMAT, VALUE_FORMAT)                      \
  void print_key_value_##KEY_TYPE##_##VALUE_TYPE(void *key, void *value)                              \
  {                                                                                                   \
    printf("Key: " KEY_FORMAT ", Value: " VALUE_FORMAT "\n", *(KEY_TYPE *)key, *(VALUE_TYPE *)value); \
  }

// DONE void print_key_value(void *key, void *value, size_t key_size, size_t value_size);
// DONE void handle_hash_or_array_map(int map_fd);
// TODO void handle_prog_array_map(int map_fd);
// TODO void handle_perf_event_array_map(int map_fd);
// TODO void handle_stack_trace_map(int map_fd);
// TODO void handle_cgroup_array_map(int map_fd);

void print_map_info(int map_fd);

#endif // MAP_PRINT_H