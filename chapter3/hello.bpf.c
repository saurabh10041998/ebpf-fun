#include <linux/bpf.c>
#include <bpf/bpf_helpers.h>

int counter = 0;

SEC("xdp")
int hello(void *ctx) {
    bpf_printk("Hello, world %d", counter)
    counter++;
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";