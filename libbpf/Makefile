.SUFFIXES: # Delete default rules for %.o

OBJDUMP=llvm-objdump-15

.PHONY: \
	all clean \
	trace trace_pipe \
	hello_world double_attach

all: hello_world double_attach

clean:
	rm *.o *.S

# `sudo` required
trace_pipe:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# `sudo` required
trace:
	sudo cat /sys/kernel/debug/tracing/trace

# `sudo` required
hello_world: hello_world.o hello_world.bpf.o
	sudo ./hello_world.o
double_attach: double_attach.o double_attach.bpf.o
	sudo ./double_attach.o
map: map.o map.bpf.o
	sudo ./map.o

%.bpf.o : %.bpf.c
	clang \
	  -target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-g \
		-O2 \
		-o $@ \
		-c $(filter %.c, $^)

%.S : %.o
	$(OBJDUMP) -D $^ > $@

%.o : %.c
	clang \
	  -lbpf \
		-g \
		-o $@ \
		$(filter %.c, $^)
