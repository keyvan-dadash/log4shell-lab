#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);
    __type(value, __u8);
} pid_filter_map SEC(".maps");

static __always_inline void try_block_and_log(struct pt_regs *ctx, const char *name) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (val) {
        bpf_override_return(ctx, -1);
    }
}

SEC("kprobe/__x64_sys_clone")
int block_clone(struct pt_regs *ctx) {
    try_block_and_log(ctx, "clone");
    return 0;
}

SEC("kprobe/__x64_sys_vfork")
int block_vfork(struct pt_regs *ctx) {
    try_block_and_log(ctx, "vfork");
    return 0;
}

SEC("kprobe/__x64_sys_fork")
int block_fork(struct pt_regs *ctx) {
    try_block_and_log(ctx, "fork");
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int block_execve(struct pt_regs *ctx) {
    try_block_and_log(ctx, "execve");
    return 0;
}

SEC("kprobe/__x64_sys_clone3")
int block_clone3(struct pt_regs *ctx) {
    try_block_and_log(ctx, "clone3");
    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int block_execveat(struct pt_regs *ctx) {
    try_block_and_log(ctx, "execveat");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

