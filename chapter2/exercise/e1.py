from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);

struct data_t {
    u32 pid;
    u32 uid;
    char command[16];
    char message[16];
};

int hello(void *ctx) {
    struct data_t data = {};
    char o_msg[16] = "odd pid message1";
    char e_msg[16] = "even pid message";
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xffffffff;
    
    bpf_get_current_comm(&data.command, sizeof(data.command));
    
    if (data.pid % 2) {
        bpf_probe_read_kernel(&data.message, sizeof(data.message), o_msg);
    } else {
        bpf_probe_read_kernel(&data.message, sizeof(data.message), e_msg);
    }

    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    event = b["output"].event(data)
    print(f"PID: {event.pid}, UID: {event.uid}, Command: {event.command.decode()}, Message: {event.message.decode()}")

b["output"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break