#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define BPFCON_MAX_PROCESSES 10240

// 进程执行审计事件
struct process_exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 action;  // ACTION_MONITOR 或 ACTION_BLOCK
    char nodename[NEW_UTS_LEN + 1];
    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
};

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

// 进程执行审计事件 ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} process_exec_events SEC(".maps");

BPF_HASH(processes, u32, struct process_info, BPFCON_MAX_PROCESSES);

struct allowed_process_key
{
  char comm[TASK_COMM_LEN];
};

BPF_HASH(process_safeguard_config_map, u32, struct process_safeguard_config, 256);
BPF_HASH(allowed_process_list, struct allowed_process_key, u32, 1024);

static inline void get_process_info(struct process_info *info) {
    struct task_struct *current_task;
    struct uts_namespace *uts_ns;
    struct nsproxy *nsproxy;

    current_task = (struct task_struct *)bpf_get_current_task();
    info->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    info->ppid = (u32)(BPF_CORE_READ(current_task, real_parent, tgid));
    BPF_CORE_READ_INTO(&info->nodename, current_task, nsproxy, uts_ns, name.nodename);

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

// 报告进程执行事件
static inline void report_process_exec_event(struct linux_binprm *bprm, __u8 action) {
    struct process_exec_event *event;

    event = bpf_ringbuf_reserve(&process_exec_events, sizeof(*event), 0);
    if (!event)
        return;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    event->ppid = (u32)(BPF_CORE_READ(current_task, real_parent, tgid));
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
    event->action = action;

    BPF_CORE_READ_INTO(&event->nodename, current_task, nsproxy, uts_ns, name.nodename);
    bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), BPF_CORE_READ(bprm, filename));
    bpf_probe_read_kernel_str(&event->parent_comm, sizeof(event->parent_comm), &parent_task->comm);

    bpf_ringbuf_submit(event, 0);
}

// 从路径中提取文件名（basename）
static inline void get_basename(const char *path, char *basename, size_t max_len) {
    int i = 0, last_slash = -1;

    // 找到最后一个 '/'
    #pragma unroll
    for (i = 0; i < TASK_COMM_LEN; i++) {
        char c;
        bpf_probe_read_kernel(&c, 1, &path[i]);
        if (c == '\0') break;
        if (c == '/') last_slash = i;
    }

    // 复制最后一个 '/' 之后的内容
    int start = (last_slash >= 0) ? last_slash + 1 : 0;
    #pragma unroll
    for (i = 0; i < TASK_COMM_LEN; i++) {
        char c;
        bpf_probe_read_kernel(&c, 1, &path[start + i]);
        basename[i] = c;
        if (c == '\0') break;
    }
    basename[TASK_COMM_LEN - 1] = '\0';
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restricted_process_bprm_check, struct linux_binprm *bprm) {
    u32 index = 0;
    struct process_safeguard_config *cfg =
        bpf_map_lookup_elem(&process_safeguard_config_map, &index);

    if (!cfg) {
        return 0;
    }

    // 仅白名单模式检查
    if (cfg->policy != POLICY_WHITELIST) {
        return 0;
    }

    // 从完整路径提取文件名
    struct allowed_process_key key = {};
    const char *filename = BPF_CORE_READ(bprm, filename);
    get_basename(filename, key.comm, sizeof(key.comm));

    u32 *allowed = bpf_map_lookup_elem(&allowed_process_list, &key);
    if (allowed) {
        return 0;  // 在白名单中，允许
    }

    // 不在白名单中
    if (cfg->mode == MODE_MONITOR) {
        // monitor 模式：记录日志，不阻断
        report_process_exec_event(bprm, 0);  // ACTION_MONITOR = 0
        return 0;
    } else {
        // block 模式：记录日志并阻断
        report_process_exec_event(bprm, 1);  // ACTION_BLOCK = 1
        return -EPERM;
    }
}

char _license[] SEC("license") = "GPL";
