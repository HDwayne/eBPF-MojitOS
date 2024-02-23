#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

struct
{
  __uint(type, BPF_MAP_TYPE_HASH); // Type de la map
  __type(key, __u32);              // PID
  __type(value, __u64);            // nombre de changements de contexte
  __uint(max_entries, 2048);       // Nombre maximum d'entrées dans la map
} pid_switch_count SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int on_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 *counter, init_val = 1;

  counter = bpf_map_lookup_elem(&pid_switch_count, &pid);
  if (counter)
  {
    // Si le PID existe déjà, incrémente le compteur
    __sync_fetch_and_add(counter, 1);
  }
  else
  {
    // Sinon, ajoute un nouveau PID avec un compteur initialisé à 1
    bpf_map_update_elem(&pid_switch_count, &pid, &init_val, BPF_ANY);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
