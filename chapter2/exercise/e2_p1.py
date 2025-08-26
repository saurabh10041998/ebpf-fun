from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello, BPF world!\\n");
    return 0;
}
"""

b = BPF(text=program)
open_at_syscall = b.get_syscall_fnname("openat")
b.attach_kprobe(event=open_at_syscall, fn_name="hello")

write_syscall = b.get_syscall_fnname("write")
b.attach_kprobe(event=write_syscall, fn_name="hello")

b.trace_print()