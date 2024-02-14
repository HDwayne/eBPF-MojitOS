#include "ebpf_lib.h"
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <stdio.h>

// Définition globale pour gérer les ressources eBPF
static struct bpf_object *g_bpf_obj = NULL;
static struct bpf_link *g_bpf_link = NULL;

struct bpf_object *ebpf_get_bpf_object(void)
{
  return g_bpf_obj;
}

// Fonction de rappel pour les messages libbpf
static int libbpf_print_cb(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

int ebpf_init(void)
{
  libbpf_set_print(libbpf_print_cb);
  return 0;
}

int ebpf_load_attach(const char *filename)
{
  struct bpf_object *obj = NULL;
  struct bpf_program *prog;
  struct bpf_link *link = NULL;
  int err;

  // Chargement de l'objet BPF
  obj = bpf_object__open(filename);
  if (libbpf_get_error(obj))
  {
    fprintf(stderr, "Failed to open eBPF program: %s\n", filename);
    return -1;
  }

  // Chargement de l'objet BPF dans le noyau
  err = bpf_object__load(obj);
  if (err)
  {
    fprintf(stderr, "Failed to load eBPF object\n");
    goto cleanup;
  }

  // Attachement du programme BPF
  prog = bpf_object__next_program(obj, NULL);
  if (!prog)
  {
    fprintf(stderr, "Failed to find a BPF program in the object\n");
    err = -1;
    goto cleanup;
  }

  link = bpf_program__attach(prog);
  if (libbpf_get_error(link))
  {
    fprintf(stderr, "Failed to attach BPF program\n");
    err = -1;
    goto cleanup;
  }

  // Stockage global pour nettoyage ultérieur
  g_bpf_obj = obj;
  g_bpf_link = link;
  return 0;

cleanup:
  if (link)
    bpf_link__destroy(link);
  if (obj)
    bpf_object__close(obj);
  return err;
}

void ebpf_cleanup(void)
{
  if (g_bpf_link)
  {
    bpf_link__destroy(g_bpf_link);
    g_bpf_link = NULL;
  }
  if (g_bpf_obj)
  {
    bpf_object__close(g_bpf_obj);
    g_bpf_obj = NULL;
  }
}
