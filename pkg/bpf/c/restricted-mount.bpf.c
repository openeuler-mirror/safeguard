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

SEC("lsm/sb_mount")
int BPF_PROG(restricted_mount, const char* dev_name, const struct path *path, const char *type, unsigned long flags, void *data)
{
    int ret = 0;
    bool find = false;
    int inum = 0, index = 0;
    struct mount_audit_event event = {};
	char cc[NAME_MAX / 4];
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    struct mount_safeguard_config *config = (struct mount_safeguard_config *)bpf_map_lookup_elem(&mount_safeguard_config_map, &index);
	if(dev_name == NULL) return ret;

	BPF_CORE_READ_INTO(&inum, current_task, nsproxy, mnt_ns, ns.inum);
    event.cgroup = bpf_get_current_cgroup_id();
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	BPF_CORE_READ_INTO(&event.nodename, current_task, nsproxy, uts_ns, name.nodename);
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
	unsigned int key = 0;
    struct file_path *paths= (struct file_path *)bpf_map_lookup_elem(&mount_denied_source_list, &key);
    if (paths == NULL) {
        return 0;
    }
    bpf_probe_read_kernel_str(&event.path, sizeof(event.path), dev_name);
    bpf_probe_read_kernel_str(cc, NAME_MAX, dev_name);

    int j = 0;
	#pragma unroll
    for (int i = 0; i < LOOP_NAME; i++) {
		if (paths->path[i] == '\0'){
			break;
		}
        if (paths->path[i] == cc[j]) {
            j = j + 1;
        } else {
            j = 0;
            continue;
        }

        if (paths->path[i+1] == '\0' || paths->path[i+1] == '|') {
            if (cc[j] == '\0' || cc[j] == '/') {
                ret = -EPERM;
                find = true;
				bpf_printk("from_path %s\n", cc);
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

    return ret;
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

SEC("lsm/move_mount")
int BPF_PROG(restricted_move_mount, const struct path *from_path, const struct path *to_path)
{
    struct mount *p;
    struct mount *old;
    const char * name;
    int index = 0, find = 0, ret = 0, inum = 0;
    struct mount_audit_event event = {};
    struct uts_namespace *uts_ns;
    struct mnt_namespace *mnt_ns;
    struct nsproxy *nsproxy;
    struct mount_safeguard_config *config = (struct mount_safeguard_config *)bpf_map_lookup_elem(&mount_safeguard_config_map, &index);

	old = real_mount(from_path->mnt);
	p = real_mount(to_path->mnt);

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);
    BPF_CORE_READ_INTO(&event.nodename, current_task, nsproxy, uts_ns, name.nodename);
    BPF_CORE_READ_INTO(&inum, current_task, nsproxy, mnt_ns, ns.inum);

    event.cgroup = bpf_get_current_cgroup_id();
    event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event.task, sizeof(event.task));
    bpf_probe_read_kernel_str(&event.parent_task, sizeof(event.parent_task), &parent_task->comm);

    #if LINUX_VERSION_CODE > VERSION_5_10
    name = BPF_CORE_READ(old, mnt_devname);
    bpf_probe_read_kernel_str(&event.path, sizeof(event.path), name);

    struct callback_ctx cb = { .path = event.path, .found = false };
    bpf_for_each_map_elem(&mount_denied_source_list, cb_check_path, &cb, 0);
    if (cb.found) {
        bpf_printk("Mount Denied: %s", cb.path);
        find = true;
        ret = -EPERM;
        goto out;
    }
    #else
    #endif

out:
    if (find && config && config->mode == MODE_MONITOR) {
        ret = 1;
    }
	event.ret = ret;
    if(ret != 0)
        bpf_perf_event_output((void *)ctx, &mount_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if(ret>0) ret = 0;

    return ret;
}
