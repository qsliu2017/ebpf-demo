#include <bpf/libbpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

static int libbpf_print(enum libbpf_print_level level, const char *s,
                        va_list ap) {
  return vfprintf(stderr, s, ap);
}

int main() {
  bool _load = false;
  libbpf_set_print(libbpf_print);

  __auto_type obj = bpf_object__open_file("hello_world.bpf.o", NULL);

  __auto_type err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "cannot load bpf object: %d\n", err);
    goto cleanup;
  }
  _load = true;

  __auto_type prog = bpf_object__find_program_by_name(obj, "helloworld");

  bpf_program__attach(prog);

  for (;;) {
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  if (_load)
    bpf_object__close(obj);
}