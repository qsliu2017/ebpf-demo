#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 2);
} my_map SEC(".maps");

SEC("kprobe/do_nanosleep")
int bpf_prog(void *ctx) {
  struct Msg {
    __u64 pid;
  } msg;

  msg.pid = bpf_get_current_pid_tgid() & (((__u64)1 << 32) - 1);
  bpf_perf_event_output(ctx, &my_map, 0, &msg, sizeof(msg));

  return 0;
}
