#include "../build/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct
{
  __uint(type, BPF_MAP_TYPE_HASH); // Type de la map
  __type(key, __u32);              // PID
  __type(value, __u64);            // nombre d'écritures sur le disque
  __uint(max_entries, 2048);       // Nombre maximum d'entrées dans la map
} pid_write_count SEC(".maps");

SEC("kprobe/__x64_sys_write")
int on_sys_write(struct pt_regs *ctx)
{
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  __u64 *counter, init_val = 1;

  counter = bpf_map_lookup_elem(&pid_write_count, &pid);
  if (counter)
  {
    // Si le compteur existe, incrémente-le
    __sync_fetch_and_add(counter, 1);
  }
  else
  {
    // Sinon, ajoute un nouvel élément pour ce PID avec un compteur initialisé à 1
    bpf_map_update_elem(&pid_write_count, &pid, &init_val, BPF_NOEXIST);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
