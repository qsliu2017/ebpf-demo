#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_nanosleep")
int helloworld(void *ctx) {
  const char greet[16] = "Hello World!\n";
  bpf_trace_printk(greet, 16);
  return 0;
}
