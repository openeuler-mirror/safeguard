#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define MAX_TRACKED_PROCESSES 10240

// 定义进程信息结构
struct process_details {
    __u32 process_id;
    __u32 parent_id;
    char node_name[NEW_UTS_LEN + 1];
    char process_name[TASK_COMM_LEN];
    char parent_name[TASK_COMM_LEN];
};

// 定义性能事件数组和哈希表
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} process_activity_logs SEC(".maps");

BPF_HASH(active_processes, u32, struct process_details, MAX_TRACKED_PROCESSES);

// 收集进程信息
static inline void gather_process_details(struct process_details *details) {
    struct task_struct *current;
    struct uts_namespace *uts_space;
    struct nsproxy *proxy_space;

    current = (struct task_struct *)bpf_get_current_task();
    details->process_id = (u32)(bpf_get_current_pid_tgid() >> 32);
    details->parent_id = (u32)(BPF_CORE_READ(current, real_parent, tgid));
    BPF_CORE_READ_INTO(&details->node_name, current, nsproxy, uts_ns, name.nodename);

    bpf_get_current_comm(&details->process_name, sizeof(details->process_name));
    struct task_struct *parent = BPF_CORE_READ(current, real_parent);
    bpf_probe_read_kernel_str(&details->parent_name, sizeof(details->parent_name), &parent->comm);
}

// 将进程信息添加到哈希表
static __always_inline struct process_details *
insert_process_entry(struct process_details *details) {
    bpf_map_update_elem(&active_processes, &details->process_id, details, BPF_NOEXIST);
    struct process_details *entry = bpf_map_lookup_elem(&active_processes, &details->process_id);
    if (!entry) {
        return NULL;
    }
    return entry;
}

// 跟踪进程分叉事件
SEC("tracepoint/sched/sched_process_fork")
int BPF_PROG(monitor_process_fork, struct bpf_raw_tracepoint_args *args) {
    struct process_details details = {0};
    gather_process_details(&details);
    insert_process_entry(&details);
    bpf_perf_event_output(ctx, &process_activity_logs, BPF_F_CURRENT_CPU, &details, sizeof(details));
    return 0;
}

// 跟踪进程执行事件
SEC("tracepoint/sched/sched_process_exec")
int BPF_PROG(monitor_process_exec, struct bpf_raw_tracepoint_args *args) {
    struct process_details details = {0};
    gather_process_details(&details);
    insert_process_entry(&details);
    bpf_perf_event_output(ctx, &process_activity_logs, BPF_F_CURRENT_CPU, &details, sizeof(details));
    return 0;
}

// 跟踪进程退出事件
SEC("tracepoint/sched/sched_process_exit")
int BPF_PROG(monitor_process_exit, struct bpf_raw_tracepoint_args *args) {
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_map_delete_elem(&active_processes, &pid);
    return 0;
}

// 定义许可证信息
char license_info[] SEC("license") = "GPL";