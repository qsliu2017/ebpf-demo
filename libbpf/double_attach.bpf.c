#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_nanosleep")
int helloworld(void *ctx) {
  const char greet[] = "Hello World!\n";
  bpf_trace_printk(greet, sizeof(greet));
  return 0;
}

SEC("kprobe/do_nanosleep")
int helloworld2(void *ctx) {
  const char greet[] = "Greeting!\n";
  bpf_trace_printk(greet, sizeof(greet));
  return 0;
}
