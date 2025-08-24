from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);

struct data_t {
    int uid;
    int pid;
    char command[16];
    char message[12];
};

int hello(void* ctx) {
    struct data_t data = {};
    char message[12] = "Hello world";
    data.uid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(data.message, sizeof(data.message), message);
    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
b = BPF(text=program)
syscall = b.get_syscall_fnname('execve')
b.attach_kprobe(event=syscall, fn_name='hello')

def print_event(cpu, data, size):
    data = b['output'].event(data)
    print(f"UID => {data.uid}, PID => {data.pid}, Command => {data.command.decode()} Message => {data.message.decode()}")

b['output'].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break

