CC = gcc
CLANG = clang
CFLAGS = -O2 -Wall
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -Iebpf
LIBS = -lbpf

all: ebpf/sensor.bpf.o ebpf/sensor_loader

ebpf/sensor.bpf.o: ebpf/sensor.bpf.c ebpf/sensor.h ebpf/event.h ebpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ebpf/sensor_loader: ebpf/sensor_loader.c ebpf/event.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f ebpf/sensor.bpf.o ebpf/sensor_loader

.PHONY: all clean
