from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(output);

int hello(void *ctx) {
    u64 counter = 0;
    struct bpf_raw_tracepoint_args *raw_ctx = ctx;
    u64 syscall_no = raw_ctx->args[1];
    u64 *p;
    p = output.lookup(&syscall_no);
    if (p) {
        counter = *p;
    }
    counter++;
    output.update(&syscall_no, &counter);
    return 0;
}
"""
b = BPF(text=program)
b.attach_raw_tracepoint("sys_enter", fn_name="hello")

while True:
    try:
        sleep(2)
        s = ""
        for k, v in b['output'].items():
           s += f"ID {k.value}: {v.value}\t"
        print(s)
    except KeyboardInterrupt:
        break