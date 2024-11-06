#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <linux/version.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} mount_events SEC(".maps");

BPF_HASH(mount_safeguard_config_map, u32, struct mount_safeguard_config, 256);
BPF_HASH(mount_denied_source_list, u32, struct file_path, 256);

/*
static inline void get_info(struct mount_audit_event *event, const char *dev_name) {
    struct uts_namespace *uts_ns;
    struct mnt_namespace *mnt_ns;
    struct nsproxy *nsproxy;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

	BPF_CORE_READ_INTO(&event->nodename, current_task, nsproxy, uts_ns, name.nodename);
	//BPF_CORE_READ_INTO(&inum, current_task, nsproxy, mnt_ns, ns.inum);

    event->cgroup = bpf_get_current_cgroup_id();
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event->task, sizeof(event->task));
    bpf_probe_read_kernel_str(&event->parent_task, sizeof(event->parent_task), &parent_task->comm);
    bpf_probe_read_kernel_str(&event->path, sizeof(event->path), dev_name);
	u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = uid_gid & 0xFFFFFFFF;
}

static int get_perm(struct mount_audit_event *event){
    int ret = -1, findex = 0, inum;
    struct mount_safeguard_config *config = (struct mount_safeguard_config *)bpf_map_lookup_elem(&mount_safeguard_config_map, &findex);
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
	BPF_CORE_READ_INTO(&inum, current_task, nsproxy, mnt_ns, ns.inum);

#if 0 && LINUX_VERSION_CODE > VERSION_5_10
	struct callback_ctx cb = { .path = event->path, .found = false };
    bpf_for_each_map_elem(&mount_denied_source_list, cb_check_path, &cb, 0);
    if (cb.found) {
        bpf_printk("Mount Denied: %s", cb.path);
        ret = -EPERM;
    }
#else
    int i = 0;
    int j = 0;
    int key = 0;
    struct file_path *paths;
    paths = (struct file_path *)bpf_map_lookup_elem(&mount_denied_source_list, &key);
    if (paths == NULL) {
        return 0;
    }

    //bpf_printk("Mount event: %s", paths->path);
    //bpf_printk("Mount Denied: %s", event->path);

    #pragma unroll
    for (i = 0; i < LOOP_NAME; i++) {
        if (paths->path[i] == '\0') {
            break;
        }
        if (paths->path[i] == '|') {
            continue;
        }
        if (paths->path[i] == event->path[j]) {
            j = j + 1;
        } else {
            j = 0;
            continue;
        }
        if (paths->path[i+1] == '\0' || paths->path[i+1] == '|') {
            if (event->path[j] == '\0' || event->path[j] == '/') {
                ret = -EPERM;
                break;
			} else {
                j = 0;
            }
        }
    }

#endif

    if (config && config->target == TARGET_CONTAINER && inum == 0xF0000000) {
        return 0;
    }

    if (ret == -EPERM && config && config->mode == MODE_MONITOR) {
        ret = 1;
    }

    return ret;
}

SEC("lsm/sb_mount")
int BPF_PROG(restricted_mount, const char *dev_name, const struct path *path) {
	int ret = 0;
    struct mount_audit_event event = {};
	get_info(&event, dev_name);
	ret = get_perm(&event);
	event.ret = ret;
	if (ret != 0)
		bpf_perf_event_output((void *)ctx, &mount_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	if(ret > 0) ret = 0;
	return ret;
}
*/

SEC("lsm/sb_mount")
int BPF_PROG(restricted_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data)
{
	//this does work until now. according to testing ret must -1 and find must be true
    int ret = -1;
    bool find = true;
    int inum = 0, index = 0;
    struct task_struct *current_task;
    struct mount_audit_event event = {};
    struct mount_safeguard_config *config = (struct mount_safeguard_config *)bpf_map_lookup_elem(&mount_safeguard_config_map, &index);

    current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

	BPF_CORE_READ_INTO(&event.nodename, current_task, nsproxy, uts_ns, name.nodename);
	BPF_CORE_READ_INTO(&inum, current_task, nsproxy, mnt_ns, ns.inum);

    event.cgroup = bpf_get_current_cgroup_id();
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event.task, sizeof(event.task));
    bpf_probe_read_kernel_str(&event.parent_task, sizeof(event.parent_task), &parent_task->comm);
    bpf_probe_read_kernel_str(&event.path, sizeof(event.path), dev_name);

#if 0 && LINUX_VERSION_CODE > VERSION_5_10
    struct callback_ctx cb = { .path = event.path, .found = false };
    bpf_for_each_map_elem(&mount_denied_source_list, cb_check_path, &cb, 0);
    if (cb.found) {
        bpf_printk("Mount Denied: %s", cb.path);
        find = true;
        ret = -EPERM;
        goto out;
    }
#else
    unsigned int i = 0;
    unsigned int j = 0;
	unsigned int key = 0;
    struct file_path *paths= (struct file_path *)bpf_map_lookup_elem(&mount_denied_source_list, &key);
    if (paths == NULL) {
        return 0;
    }

#pragma unroll
    for (i = 0; i < LOOP_NAME; i++) {
        if (paths->path[i] == '\0') {
            break;
        }
        if (paths->path[i] == '|') {
            continue;
        }
        if (paths->path[i] == event.path[j]) {
            j = j + 1;
        } else {
            j = 0;
            continue;
        }

        if (paths->path[i+1] == '\0' || paths->path[i+1] == '|') {
            if (event.path[j] == '\0' || event.path[j] == '/') {
                ret = -EPERM;
                find = true;
                break;
            } else {
                j = 0;
            }
        }
    }
#endif
out:
    if (config && config->target == TARGET_CONTAINER && inum == 0xF0000000) {
        return 0;
    }

    if (find && config && config->mode == MODE_MONITOR) {
        ret = 1;
    }
	event.ret = ret;
	if(ret != 0)
		bpf_perf_event_output((void *)ctx, &mount_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	if(ret >0) ret = 0;
    return 0;
}
