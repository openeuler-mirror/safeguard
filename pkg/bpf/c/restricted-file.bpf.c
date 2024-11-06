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
} fileopen_events SEC(".maps");

BPF_HASH(fileopen_safeguard_config_map, u32, struct fileopen_safeguard_config, 256);
BPF_HASH(allowed_access_files, u32, struct file_path, 256);
BPF_HASH(denied_access_files, u32, struct file_path, 256);

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct buffer);
  __uint(max_entries, 1);
} heaps_map SEC(".maps");

static struct buffer *get_buffer() {
  u32 zero = 0;
  return (struct buffer *)bpf_map_lookup_elem(&heaps_map, &zero);
}

static inline void get_file_info(struct file_open_audit_event *event){
    struct uts_namespace *uts_ns;
    struct mnt_namespace *mnt_ns;
    struct nsproxy *nsproxy;

    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

    BPF_CORE_READ_INTO(&event->nodename, current_task, nsproxy, uts_ns, name.nodename);

    event->cgroup = bpf_get_current_cgroup_id();
    event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&event->task, sizeof(event->task));
    bpf_probe_read_kernel_str(&event->parent_task, sizeof(event->parent_task), &parent_task->comm);
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xFFFFFFFF;
}

static int get_perm(struct file_open_audit_event *event) {
    int ret = 0, findex = 0;
    bool find = false;
    struct fileopen_safeguard_config *config =
		(struct fileopen_safeguard_config *)bpf_map_lookup_elem(&fileopen_safeguard_config_map, &findex);
#if LINUX_VERSION_CODE > VERSION_5_10
	struct callback_ctx cb = { .path = event->path, .found = false};
	cb.found = false;
	bpf_for_each_map_elem(&denied_access_files, cb_check_path, &cb, 0);
	if (cb.found) {
		bpf_printk("Access Denied: %s\n", cb.path);
		ret = -EPERM;
		find = true;
		goto out;
	}

	bpf_for_each_map_elem(&allowed_access_files, cb_check_path, &cb, 0);
	if (cb.found) {
		ret = 0;
		find = true;
		goto out;
	}
#else
    unsigned int key = 0;
    struct file_path *paths;
    paths = (struct file_path *)bpf_map_lookup_elem(&denied_access_files, &key);
    if (paths == NULL) {
		return 0;
    }

	//bpf_printk("denied files: %s\n", paths->path);
	//bpf_printk("event files: %s\n", event->path);
    unsigned int i = 0;
    unsigned int j = 0;

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
				find = true;
				break;
			} else {
				j = 0;
			}
		}
	}
#endif

out:
    if (find && config && config->mode == MODE_MONITOR) {
        ret = 1;
    }
    return ret;
}

static inline int get_file_perm(struct file_open_audit_event *event,struct file *file){
#if LINUX_VERSION_CODE > VERSION_5_10
	if (bpf_d_path(&file->f_path, (char *)event->path, NAME_MAX) < 0) { /* get event->path from file->f_path */
		return 0;
	}
#else
    struct path *path = __builtin_preserve_access_index(&file->f_path);
    struct buffer *string_buf = get_buffer();
    if (string_buf == NULL) { return 0; }
    u_char *file_path = NULL;
    get_path_str_from_path(&file_path, path, string_buf, NULL);
    bpf_probe_read(event->path, sizeof(event->path), file_path);
#endif

	return get_perm(event);
}

static inline int get_path_perm(struct file_open_audit_event *event, const struct path *path, struct dentry *dentry){
#if LINUX_VERSION_CODE > VERSION_5_10
	if (bpf_d_path(path, (char *)event->path, NAME_MAX) < 0) { /* get event->path from file->f_path */
		return 0;
	}
#else
    struct buffer *string_buf = get_buffer();
    if (string_buf == NULL) { return 0; }
    u_char *file_path = NULL;
    get_path_str_from_path(&file_path, path, string_buf, dentry);
    bpf_probe_read(event->path, sizeof(event->path), file_path);
#endif

	return get_perm(event);
}

#define PROG_CODE \
	int ret = 0; \
    struct file_open_audit_event event = {}; \
    get_file_info(&event); \
    ret = get_file_perm(&event, file); \
	event.ret = ret; \
    if (ret != 0) \
		bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event)); \
	if (ret > 0) ret = 0; \
    return ret;

#define PROG_CODE_A \
	int ret = 0; \
    struct file_open_audit_event event = {};\
    get_file_info(&event);\
    ret = get_path_perm(&event, dir, dentry);\
	event.ret = ret; \
    if (ret != 0)\
		bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event));\
	if (ret > 0) ret = 0;\
    return ret;

SEC("lsm/file_open")
int BPF_PROG(restricted_file_open, struct file *file)
{
	PROG_CODE
}

SEC("lsm/path_unlink")
int BPF_PROG(restricted_path_unlink, const struct path *dir, struct dentry *dentry)
{
	PROG_CODE_A
}

SEC("lsm/path_rmdir")
int BPF_PROG(restricted_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	PROG_CODE_A
}

SEC("lsm/path_rename")
int BPF_PROG(restricted_path_rename, const struct path *dir, struct dentry *dentry)
{
	PROG_CODE_A
}

SEC("lsm/file_receive")
int BPF_PROG(restricted_file_receive, struct file *file)
{
	PROG_CODE
}

SEC("lsm/mmap_file")
int BPF_PROG(restricted_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
	PROG_CODE
}

SEC("lsm/file_ioctl")
int BPF_PROG(restricted_file_ioctl, struct file *file, unsigned int cmd, unsigned long arg)
{
	PROG_CODE
}
