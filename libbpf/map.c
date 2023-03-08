#include <bpf/libbpf.h>
#include <stdio.h>

#define ERROR() fprintf(stderr, "%s:%d\n", __FILE__, __LINE__)

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size) {
  struct {
    __u64 pid;
  } *e = data;

  printf("%s:%d cpu=%d size=%d pid=%llu\n", __FILE__, __LINE__, cpu, size,
         e->pid);
}

int main() {
  __auto_type obj = bpf_object__open_file("map.bpf.o", NULL);
  if (bpf_object__load(obj)) {
    ERROR();
    return 1;
  }

  __auto_type map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");
  if (map_fd < 0) {
    ERROR();
    return 2;
  }

  __auto_type prog = bpf_object__find_program_by_name(obj, "bpf_prog");
  if (libbpf_get_error(prog)) {
    ERROR();
    return 3;
  }

  if (libbpf_get_error(bpf_program__attach(prog))) {
    ERROR();
    return 4;
  }

  __auto_type pb =
      perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
  if (libbpf_get_error(pb)) {
    ERROR();
    return 5;
  }

  while (perf_buffer__poll(pb, 1000) >= 0)
    ;
  return 0;
}
