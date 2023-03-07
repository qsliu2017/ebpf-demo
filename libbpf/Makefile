.SUFFIXES: # Delete default rules for %.o

.PHONY: \
	all clean \
	trace trace_pipe \
	hello_world

all: hello_world

clean:
	rm *.o

# `sudo` required
trace_pipe:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# `sudo` required
trace:
	sudo cat /sys/kernel/debug/tracing/trace

# `sudo` required
hello_world: hello_world.o hello_world.bpf.o
	sudo ./hello_world.o

%.bpf.o : %.bpf.c
	clang \
	  -target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-O2 \
		-o $@ \
		-c $(filter %.c, $^)

%.o : %.c
	clang \
	  -lbpf \
		-o $@ \
		$(filter %.c, $^)
