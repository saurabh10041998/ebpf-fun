from bcc import BPF
from time import sleep

program = r"""
enum syscalls {
    SYSCALL_OPENAT = 0,
    SYSCALL_WRITE = 1,
    SYSCALL_EXECVE = 2
};

BPF_HASH(output, enum syscalls, u64);

int hello_for_openat(void *ctx) {
    u64* p;
    u64 counter = 0;

    enum syscalls key = SYSCALL_OPENAT;
    p = output.lookup(&key);
    if (p) {
        counter = *p;
    }
    counter++;
    output.update(&key, &counter);
    return 0;
}

int hello_for_execve(void *ctx) {
    u64* p;
    u64 counter = 0;

    enum syscalls key = SYSCALL_EXECVE;
    p = output.lookup(&key);
    if (p) {
        counter = *p;
    }
    counter++;
    output.update(&key, &counter);
    return 0;
}

int hello_for_write(void *ctx) {
    u64* p;
    u64 counter = 0;

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
syscall_execve = b.get_syscall_fnname("execve")
syscall_write = b.get_syscall_fnname("write")

b.attach_kprobe(event=syscall_openat, fn_name="hello_for_openat")
b.attach_kprobe(event=syscall_execve, fn_name="hello_for_execve")
b.attach_kprobe(event=syscall_write, fn_name="hello_for_write")

# write lambda to print syscall name according enum in program
print_syscall_name = lambda k: {
    0: "openat",
    1: "write",
    2: "execve"
}.get(k, "unknown")

while True:
    try:
        sleep(2)
        s = ''
        for k, v in b["output"].items():
            s += f"Syscall: {print_syscall_name(k.value)}, Count: {v.value}\n"
        print(s)
    except KeyboardInterrupt:
        break