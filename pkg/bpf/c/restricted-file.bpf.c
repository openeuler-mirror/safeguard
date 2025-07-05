#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <linux/version.h>

// 定义许可证信息
char license_info[] SEC("license") = "Dual BSD/GPL";

// 定义性能事件数组和哈希表
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} file_access_logs SEC(".maps");

BPF_HASH(file_security_config, u32, struct fileopen_safeguard_config, 256);
BPF_HASH(permitted_file_paths, u32, struct file_path, 256);
BPF_HASH(blocked_file_paths, u32, struct file_path, 256);

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct buffer);
    __uint(max_entries, 1);
} temp_storage SEC(".maps");

// 获取临时缓冲区
static struct buffer *fetch_temp_buffer() {
    u32 index = 0;
    return (struct buffer *)bpf_map_lookup_elem(&temp_storage, &index);
}

// 获取文件相关信息
static inline void collect_file_details(struct file_open_audit_event *record) {
    struct uts_namespace *uts_space;
    struct mnt_namespace *mnt_space;
    struct nsproxy *proxy_space;

    // 获取当前任务和父任务
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(current, real_parent);

    // 读取节点名称
    BPF_CORE_READ_INTO(&record->nodename, current, nsproxy, uts_ns, name.nodename);

    // 填充记录信息
    record->cgroup = bpf_get_current_cgroup_id();
    record->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&record->task, sizeof(record->task));
    bpf_probe_read_kernel_str(&record->parent_task, sizeof(record->parent_task), &parent->comm);
    u64 uid_gid = bpf_get_current_uid_gid();
    record->uid = uid_gid & 0xFFFFFFFF;
}

// 检查文件访问权限
static int evaluate_access(struct file_open_audit_event *record) {
    int result = 0, config_index = 0;
    bool is_denied = false;
    struct fileopen_safeguard_config *security_config =
        (struct fileopen_safeguard_config *)bpf_map_lookup_elem(&file_security_config, &config_index);

#if LINUX_VERSION_CODE > VERSION_5_10
    // 使用回调函数检查路径是否在黑名单中
    struct callback_ctx path_check = { .path = record->path, .found = false };
    path_check.found = false;
    bpf_for_each_map_elem(&blocked_file_paths, cb_check_path, &path_check, 0);
    if (path_check.found) {
        bpf_printk("File Access Denied: %s\n", path_check.path);
        result = -EPERM;
        is_denied = true;
        goto audit_output;
    }
#else
    // 手动检查路径是否在黑名单中
    unsigned int map_key = 0;
    struct file_path *path_list = (struct file_path *)bpf_map_lookup_elem(&blocked_file_paths, &map_key);
    if (path_list == NULL) {
        return 0;
    }

    unsigned int path_index = 0;
    unsigned int match_index = 0;

    #pragma unroll
    for (path_index = 0; path_index < LOOP_NAME; path_index++) {
        if (path_list->path[path_index] == '\0') {
            break;
        }
        if (path_list->path[path_index] == '|') {
            continue;
        }
        if (path_list->path[path_index] == record->path[match_index]) {
            match_index++;
        } else {
            match_index = 0;
            continue;
        }
        if (path_list->path[path_index + 1] == '\0' || path_list->path[path_index + 1] == '|') {
            if (record->path[match_index] == '\0' || record->path[match_index] == '/') {
                result = -EPERM;
                is_denied = true;
                break;
            } else {
                match_index = 0;
            }
        }
    }
#endif

audit_output:
    // 如果是监控模式且发现违规，设置返回值为 1
    if (is_denied && security_config && security_config->mode == MODE_MONITOR) {
        result = 1;
    }
    return result;
}

// 检查文件权限（基于文件结构）
static inline int assess_file_access(struct file_open_audit_event *record, struct file *file_ptr) {
#if 0 && LINUX_VERSION_CODE > VERSION_5_10
    if (bpf_d_path(&file_ptr->f_path, (char *)record->path, NAME_MAX) < 0) {
        return 0;
    }
#else
    struct path *file_path = __builtin_preserve_access_index(&file_ptr->f_path);
    struct buffer *temp_buf = fetch_temp_buffer();
    if (temp_buf == NULL) {
        return 0;
    }
    u_char *path_str = NULL;
    get_path_str_from_path(&path_str, file_path, temp_buf, NULL);
    bpf_probe_read(record->path, sizeof(record->path), path_str);
#endif

    return evaluate_access(record);
}

// 检查文件权限（基于路径结构）
static inline int assess_path_access(struct file_open_audit_event *record, const struct path *file_path, struct dentry *entry) {
#if 0 && LINUX_VERSION_CODE > VERSION_5_10
    if (bpf_d_path(file_path, (char *)record->path, NAME_MAX) < 0) {
        return 0;
    }
#else
    struct buffer *temp_buf = fetch_temp_buffer();
    if (temp_buf == NULL) {
        return 0;
    }
    u_char *path_str = NULL;
    get_path_str_from_path(&path_str, file_path, temp_buf, entry);
    bpf_probe_read(record->path, sizeof(record->path), path_str);
#endif

    return evaluate_access(record);
}

// 定义通用逻辑宏
#define FILE_ACCESS_LOGIC \
    int result = 0; \
    struct file_open_audit_event audit_record = {0}; \
    collect_file_details(&audit_record); \
    result = assess_file_access(&audit_record, file_ptr); \
    audit_record.ret = result; \
    if (result != 0) \
        bpf_perf_event_output((void *)ctx, &file_access_logs, BPF_F_CURRENT_CPU, &audit_record, sizeof(audit_record)); \
    if (result > 0) result = 0; \
    return result;

#define PATH_ACCESS_LOGIC \
    int result = 0; \
    struct file_open_audit_event audit_record = {0}; \
    collect_file_details(&audit_record); \
    result = assess_path_access(&audit_record, dir_path, dir_entry); \
    audit_record.ret = result; \
    if (result != 0) \
        bpf_perf_event_output((void *)ctx, &file_access_logs, BPF_F_CURRENT_CPU, &audit_record, sizeof(audit_record)); \
    if (result > 0) result = 0; \
    return result;

// LSM 钩子函数：限制文件打开
SEC("lsm/file_open")
int BPF_PROG(control_file_open, struct file *file_ptr) {
    FILE_ACCESS_LOGIC
}

// LSM 钩子函数：限制路径删除
SEC("lsm/path_unlink")
int BPF_PROG(control_path_unlink, const struct path *dir_path, struct dentry *dir_entry) {
    PATH_ACCESS_LOGIC
}

// LSM 钩子函数：限制目录删除
SEC("lsm/path_rmdir")
int BPF_PROG(control_path_rmdir, const struct path *dir_path, struct dentry *dir_entry) {
    PATH_ACCESS_LOGIC
}

// LSM 钩子函数：限制路径重命名
SEC("lsm/path_rename")
int BPF_PROG(control_path_rename, const struct path *dir_path, struct dentry *dir_entry) {
    PATH_ACCESS_LOGIC
}

// LSM 钩子函数：限制文件接收
SEC("lsm/file_receive")
int BPF_PROG(control_file_receive, struct file *file_ptr) {
    FILE_ACCESS_LOGIC
}

// LSM 钩子函数：限制文件映射
SEC("lsm/mmap_file")
int BPF_PROG(control_mmap_file, struct file *file_ptr, unsigned long req_prot,
             unsigned long prot, unsigned long flags) {
    FILE_ACCESS_LOGIC
}

// LSM 钩子函数：限制文件 IO 控制
SEC("lsm/file_ioctl")
int BPF_PROG(control_file_ioctl, struct file *file_ptr, unsigned int cmd, unsigned long arg) {
    FILE_ACCESS_LOGIC
}