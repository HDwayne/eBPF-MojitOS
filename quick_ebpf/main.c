#include <signal.h>
#include <unistd.h> // for sleep()

#include "libs/map_print.h"
#include "build/ebpf_programs_autogen.h"

// -----------------  SIGNAL HANDLING -----------------

volatile sig_atomic_t end_loop;

void sig_handler(int signo)
{
  end_loop = 1;
}

static int my_libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

// -----------------------  MAIN -----------------------

int main(int argc, char **argv)
{
  signal(SIGINT, sig_handler);

  int err = 0;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(my_libbpf_print);

  for (int i = 0; i < sizeof(ebpf_programs) / sizeof(ebpf_programs[0]); i++)
  {
    struct bpf_program_data *pdata = &ebpf_programs[i];
    pdata->skel = pdata->skeleton_open_and_load();

    if (!pdata->skel)
    {
      fprintf(stderr, "Failed to open and load BPF skeleton for %s\n", pdata->name);
      err = -1;
      goto cleanup;
    }

    if (pdata->skeleton_attach(pdata->skel))
    {
      fprintf(stderr, "Failed to attach BPF skeleton for %s\n", pdata->name);
      pdata->skeleton_destroy(pdata->skel);
      pdata->skel = NULL;
      err = -1;
      goto cleanup;
    }

    printf("%s eBPF program loaded and attached successfully\n", pdata->name);
  }

  while (!end_loop)
  {
    for (int i = 0; i < sizeof(ebpf_programs) / sizeof(ebpf_programs[0]); i++)
    {

      if (!ebpf_programs[i].skel)
      {
        fprintf(stderr, "Failed to open and load the skeleton\n");
        continue;
      }
      fprintf(stdout, "processing program: %s\n", ebpf_programs[i].name);

      int map_fd = ebpf_programs[i].get_map_fd(ebpf_programs[i].skel);
      if (map_fd < 0)
      {
        fprintf(stderr, "Failed to get map fd for %s\n", ebpf_programs[i].name);
        continue;
      }
      else
      {
        fprintf(stdout, "map_fd: %d\n", map_fd);
        print_map_info(map_fd);
      }
    }
    sleep(5);
  }

  fprintf(stdout, "Cleaning up and detaching eBPF programs\n");

cleanup:
  for (int i = 0; i < sizeof(ebpf_programs) / sizeof(ebpf_programs[0]); i++)
  {
    if (ebpf_programs[i].skel)
    {
      ebpf_programs[i].skeleton_destroy(ebpf_programs[i].skel);
      printf("%s eBPF program cleaned up\n", ebpf_programs[i].name);
    }
  }

  return err;
}
