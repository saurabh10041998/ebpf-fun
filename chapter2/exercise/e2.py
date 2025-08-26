from bcc import BPF
from time import sleep

program = r"""
enum syscalls {
    SYSCALL_OPENAT,
    SYSCALL_WRITE,
};

BPF_HASH(output, enum syscalls, u64);

int hello_for_openat(void *ctx) {
    u64 counter = 0;
    u64* p;

    enum syscalls key = SYSCALL_OPENAT;
    p = output.lookup(&key);
    if (p) {
        counter = *p;
    }
    counter++;
    output.update(&key, &counter);
    return 0;
}

int hello_for_write(void *ctx) {
    u64 counter = 0;
    u64* p;
    enum syscalls key = SYSCALL_WRITE;
    p = output.lookup(&key);
    if (p) {
        counter = *p;
    }
    counter++;
    output.update(&key, &counter);
    return 0;
}
"""

b = BPF(text=program)
syscall_openat = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")

b.attach_kprobe(event=syscall_openat, fn_name="hello_for_openat")
b.attach_kprobe(event=syscall_write, fn_name="hello_for_write")

while True:
    try:
        sleep(2)
        s = ""
        for k, v in b["output"].items():
            s += f"Syscall: {k}, Count: {v.value}\n"
        print(s)
    except KeyboardInterrupt:
        exit()