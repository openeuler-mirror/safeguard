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
} mount_audit_events SEC(".maps");

BPF_HASH(mount_protection_config, u32, struct mount_safeguard_config, 256);
BPF_HASH(mount_blocked_paths, u32, struct file_path, 256);

SEC("lsm/sb_mount")
int BPF_PROG(control_mount, const char* device_name, const struct path *mnt_path, const char *fs_type, unsigned long mount_flags, void *mount_data)
{
    int result = 0;
    bool path_matched = false;
    int namespace_id = 0, config_idx = 0;
    struct mount_audit_event audit_record = {};
    char device_buffer[DEV_LEN];

    struct task_struct *current_process = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_process = BPF_CORE_READ(current_process, real_parent);

    struct mount_safeguard_config *protection_config = (struct mount_safeguard_config *)bpf_map_lookup_elem(&mount_protection_config, &config_idx);
    if (!device_name) return result;

    BPF_CORE_READ_INTO(&namespace_id, current_process, nsproxy, mnt_ns, ns.inum);

    audit_record.cgroup = bpf_get_current_cgroup_id();
    audit_record.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    BPF_CORE_READ_INTO(&audit_record.nodename, current_process, nsproxy, uts_ns, name.nodename);
    bpf_get_current_comm(&audit_record.task, sizeof(audit_record.task));
    bpf_probe_read_kernel_str(&audit_record.parent_task, sizeof(audit_record.parent_task), &parent_process->comm);
    bpf_probe_read_kernel_str(&audit_record.path, sizeof(audit_record.path), device_name);

#if 0 && LINUX_VERSION_CODE > VERSION_5_10
    // 使用回调遍历拒绝路径列表（高版本内核支持）
    struct callback_ctx path_check = { .path = audit_record.path, .found = false };
    bpf_for_each_map_elem(&mount_blocked_paths, cb_check_path, &path_check, 0);
    if (path_check.found) {
        bpf_printk("Mount Operation Denied: %s", path_check.path);
        path_matched = true;
        result = -EPERM;
        goto audit_exit;
    }
#else
    unsigned int path_key = 0;
    struct file_path *blocked_paths = (struct file_path *)bpf_map_lookup_elem(&mount_blocked_paths, &path_key);
    if (!blocked_paths) {
        return 0;
    }
    bpf_probe_read_kernel_str(&audit_record.path, sizeof(audit_record.path), device_name);
    bpf_probe_read_kernel_str(device_buffer, DEV_LEN, device_name);

    int match_pos = 0;
    #pragma unroll
    for (int idx = 0; idx < LOOP_NAME; idx++) {
        if (blocked_paths->path[idx] == '\0') {
            break;
        }
        if (blocked_paths->path[idx] == device_buffer[match_pos]) {
            match_pos++;
        } else {
            match_pos = 0;
            continue;
        }

        if (blocked_paths->path[idx + 1] == '\0' || blocked_paths->path[idx + 1] == '|') {
            if (device_buffer[match_pos] == '\0' || device_buffer[match_pos] == '/') {
                result = -EPERM;
                path_matched = true;
                break;
            } else {
                match_pos = 0;
            }
        }
    }
#endif

audit_exit:
    if (protection_config && protection_config->target == TARGET_CONTAINER && namespace_id == 0xF0000000) {
        return 0;
    }

    if (path_matched && protection_config && protection_config->mode == MODE_MONITOR) {
        result = 1;
    }

    audit_record.ret = result;
    if (result != 0) {
        bpf_perf_event_output((void *)ctx, &mount_audit_events, BPF_F_CURRENT_CPU, &audit_record, sizeof(audit_record));
    }
    if (result > 0) result = 0;

    return result;
}

// 辅助函数：将vfsmount转换为mount结构
static inline struct mount *get_real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

// 限制挂载移动操作
SEC("lsm/move_mount")
int BPF_PROG(control_move_mount, const struct path *source_path, const struct path *dest_path)
{
    const char *device_name;
    bool path_matched = false;
    int config_idx = 0, result = 0;
    int namespace_id = 0;
    struct mount_audit_event audit_record = {};
    struct mount_safeguard_config *protection_config = (struct mount_safeguard_config *)bpf_map_lookup_elem(&mount_protection_config, &config_idx);

    struct mount *source_mount = get_real_mount(source_path->mnt);
    struct mount *dest_mount = get_real_mount(dest_path->mnt);

    struct task_struct *current_process = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_process = BPF_CORE_READ(current_process, real_parent);
    BPF_CORE_READ_INTO(&audit_record.nodename, current_process, nsproxy, uts_ns, name.nodename);
    BPF_CORE_READ_INTO(&namespace_id, current_process, nsproxy, mnt_ns, ns.inum);

    audit_record.cgroup = bpf_get_current_cgroup_id();
    audit_record.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&audit_record.task, sizeof(audit_record.task));
    bpf_probe_read_kernel_str(&audit_record.parent_task, sizeof(audit_record.parent_task), &parent_process->comm);

    device_name = BPF_CORE_READ(source_mount, mnt_devname);
    bpf_probe_read_kernel_str(&audit_record.path, sizeof(audit_record.path), device_name);

#if LINUX_VERSION_CODE > VERSION_5_10
    // 使用回调遍历拒绝路径列表（高版本内核支持）
    struct callback_ctx path_check = { .path = audit_record.path, .found = false };
    bpf_for_each_map_elem(&mount_blocked_paths, cb_check_path, &path_check, 0);
    if (path_check.found) {
        bpf_printk("Mount Move Operation Denied: %s", path_check.path);
        path_matched = true;
        result = -EPERM;
        goto audit_exit;
    }
#else
    char device_buffer[DEV_LEN];
    unsigned int path_key = 0;
    struct file_path *blocked_paths = (struct file_path *)bpf_map_lookup_elem(&mount_blocked_paths, &path_key);
    if (!blocked_paths) {
        return 0;
    }
    bpf_probe_read_kernel_str(device_buffer, DEV_LEN, device_name);

    int match_pos = 0;
    #pragma unroll
    for (int idx = 0; idx < LOOP_NAME; idx++) {
        if (blocked_paths->path[idx] == '\0') {
            break;
        }
        if (blocked_paths->path[idx] == device_buffer[match_pos]) {
            match_pos++;
        } else {
            match_pos = 0;
            continue;
        }

        if (blocked_paths->path[idx + 1] == '\0' || blocked_paths->path[idx + 1] == '|') {
            if (device_buffer[match_pos] == '\0' || device_buffer[match_pos] == '/') {
                result = -EPERM;
                path_matched = true;
                break;
            } else {
                match_pos = 0;
            }
        }
    }
#endif

audit_exit:
    if (path_matched && protection_config && protection_config->mode == MODE_MONITOR) {
        result = 1;
    }

    audit_record.ret = result;
    if (result != 0) {
        bpf_perf_event_output((void *)ctx, &mount_audit_events, BPF_F_CURRENT_CPU, &audit_record, sizeof(audit_record));
    }
    if (result > 0) result = 0;

    return result;
}