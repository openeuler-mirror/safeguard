#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define BPFCON_MAX_PROCESSES 10240


struct process_info {
    __u32 pid;
    __u32 ppid;
    char nodename[NEW_UTS_LEN + 1];
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} process_events SEC(".maps");

BPF_HASH(processes, u32, struct process_info, BPFCON_MAX_PROCESSES);

static inline void get_process_info(struct process_info *info) {
    struct task_struct *current_task;
    struct uts_namespace *uts_ns;
    struct nsproxy *nsproxy;

    current_task = (struct task_struct *)bpf_get_current_task();
    info->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    info->ppid = (u32)(BPF_CORE_READ(current_task, real_parent, tgid));
    BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
    BPF_CORE_READ_INTO(&uts_ns, nsproxy, uts_ns);
    BPF_CORE_READ_INTO(&info->nodename, uts_ns, name.nodename);
    
    bpf_get_current_comm(&info->comm, sizeof(info->comm));
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    bpf_probe_read_kernel_str(&info->parent_comm, sizeof(info->parent_comm), &parent_task->comm);
}
 
static __always_inline struct process_info *
add_process_to_map(struct process_info *info)
{
    bpf_map_update_elem(&processes, &info->pid, info, BPF_NOEXIST);
    struct process_info *process = bpf_map_lookup_elem(&processes, &info->pid);
    if (!process)
        return NULL;
    return process;
}

SEC("tracepoint/sched/sched_process_fork")
int BPF_PROG(restricted_process_fork, struct bpf_raw_tracepoint_args *args) {
    struct process_info info = {};
    get_process_info(&info);
    add_process_to_map(&info);
    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int BPF_PROG(restricted_process_exec, struct bpf_raw_tracepoint_args *args) {
    struct process_info info = {};
    get_process_info(&info);
    add_process_to_map(&info);
    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int BPF_PROG(restricted_process_exit, struct bpf_raw_tracepoint_args *args) {

    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_map_delete_elem(&processes, &pid);
    return 0;
}

// SEC("lsm/task_alloc")
// int BPF_PROG(restricted_task_alloc, struct task_struct *task, unsigned long clone_flags) {
    
//     return -EPERM;
// }

char _license[] SEC("license") = "GPL";
