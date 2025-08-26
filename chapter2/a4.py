from bcc import BPF
import ctypes as ct

program = r"""
BPF_PROG_ARRAY(syscall, 300);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d\n", opcode);
    return 0;
}

int hello_execve(void *ctx) {
    bpf_trace_printk("Another execve syscall\n");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    if (ctx->args[1] == 222) {
        bpf_trace_printk("Creating a timer\n");
    } else if (ctx->args[1] == 226) {
        bpf_trace_printk("Deleting a timer\n");
    } else {
        bpf_trace_printk("Unknown timer operation\n");
    }
    return 0;
}

int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")
prog_array = b.get_table("syscall")
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(1)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(0)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(281)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(232)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(35)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(202)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(13)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(14)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(271)] = ct.c_int(ignore_fn.fd)


b.trace_print()