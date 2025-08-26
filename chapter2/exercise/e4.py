from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(output);

RAW_TRACEPOINT_PROBE(sys_enter) {
    u64 syscall_no = ctx->args[1];
    u64 counter = 0;
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

while True:
    try:
        sleep(2)
        s = ""
        for k, v in b['output'].items():
            s += f"ID {k.value}: {v.value}\t"
        print(s)
    except KeyboardInterrupt:
        break