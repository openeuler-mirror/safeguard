#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define FILE_NAME_LEN	32
#define NAME_MAX 255

struct file_path {
    unsigned char path[NAME_MAX];
};


struct callback_ctx {
    unsigned char *path;
    bool found;
};

struct file_open_audit_event {
    //u64 cgroup;
    u32 pid;
    u32 uid;
    int ret;
    char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    char parent_task[TASK_COMM_LEN];
    unsigned char path[NAME_MAX];
}; //512 stack size restrict, now [479 - 64(cgroup) + 32(uid)] + other_stack

struct fileopen_safeguard_config {
    u32 mode;
    u32 target;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} fileopen_events SEC(".maps");

BPF_HASH(fileopen_safeguard_config_map, u32, struct fileopen_safeguard_config, 256);
BPF_HASH(allowed_access_files, u32, struct file_path, 256);
BPF_HASH(denied_access_files, u32, struct file_path, 256);
BPF_HASH(allowed_access_files_uid, u32, u32, 256);
BPF_HASH(denied_access_files_uid, u32, u32, 256);

static u64 cb_check_path(struct bpf_map *map, u32 *key, struct file_path *map_path, struct callback_ctx *ctx) {
    size_t size = strlen(map_path->path, NAME_MAX);
    if (strcmp(map_path->path, ctx->path, size) == 0) {
        ctx->found = true;
    }

    return 0;
}

static inline void get_file_info(struct file_open_audit_event *event){
    struct task_struct *current_task;
    struct uts_namespace *uts_ns;
    struct mnt_namespace *mnt_ns;
    struct nsproxy *nsproxy;

    current_task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
    BPF_CORE_READ_INTO(&uts_ns, nsproxy, uts_ns);
    BPF_CORE_READ_INTO(&event->nodename, uts_ns, name.nodename);
    BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
    // BPF_CORE_READ_INTO(&inum, mnt_ns, ns.inum);
    //event->cgroup = bpf_get_current_cgroup_id();
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event->task, sizeof(event->task));
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    bpf_probe_read_kernel_str(&event->parent_task, sizeof(event->parent_task), &parent_task->comm);
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
}

static inline int get_file_perm(struct file_open_audit_event *event,struct file *file){
    int ret = -1;
    int findex = 0;
    struct fileopen_safeguard_config *config = (struct fileopen_safeguard_config *)bpf_map_lookup_elem(&fileopen_safeguard_config_map, &findex);

    if (bpf_d_path(&file->f_path, (char *)event->path, NAME_MAX) < 0) { /* get event->path from file->f_path */
        return 0;
    }
    struct callback_ctx cb = { .path = event->path, .found = false};
    cb.found = false;
    bpf_for_each_map_elem(&denied_access_files, cb_check_path, &cb, 0);
    u32 uid = event->uid;
    if (cb.found && bpf_map_lookup_elem(&denied_access_files_uid, &uid)) {
        bpf_printk("Access Denied: %s\n", cb.path);
        ret = -EPERM;
        goto out;
    }

    bpf_for_each_map_elem(&allowed_access_files, cb_check_path, &cb, 0);
    if (cb.found) {
        ret = 0;
        goto out;
    }


out:
    if (config && config->mode == MODE_MONITOR) {
        ret = 0;
    }
    return ret;
}

SEC("lsm/file_open")
int BPF_PROG(restricted_file_open, struct file *file)
{
    struct file_open_audit_event event = {};
    get_file_info(&event);
    event.ret = get_file_perm(&event, file);
    bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return event.ret;
}

SEC("lsm/file_receive")
int BPF_PROG(restricted_file_receive, struct file *file)
{
    struct file_open_audit_event event = {};
    get_file_info(&event);
    event.ret = get_file_perm(&event, file);
    bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return event.ret;
}


SEC("lsm/mmap_file")
int BPF_PROG(restricted_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    struct file_open_audit_event event = {};
    get_file_info(&event);
    event.ret = get_file_perm(&event, file);
    bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return event.ret;
}


SEC("lsm/file_ioctl")
int BPF_PROG(restricted_file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
{
    struct file_open_audit_event event = {};
    get_file_info(&event);
    event.ret = get_file_perm(&event, file);
    bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return event.ret;
}
