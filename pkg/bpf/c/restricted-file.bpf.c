#include "common_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <linux/version.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define NAME_MAX 255
#define LOOP_NAME 80

struct file_path {
    unsigned char path[NAME_MAX];
};

struct callback_ctx {
    unsigned char *path;
    bool found;
};

struct file_open_audit_event {
    u64 cgroup;
    u32 pid;
    u32 uid;
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



#define MAX_PATH_SIZE 4096 // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

struct buffer {
  u8 data[MAX_PERCPU_ARRAY_SIZE];
};

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

static long get_path_str_from_path(u_char **path_str, const struct path *path, struct buffer *out_buf, struct dentry *append) {
	long ret;
	struct dentry *dentry, *dentry_parent, *dentry_mnt;
	struct vfsmount *vfsmnt;
	struct mount *mnt, *mnt_parent;
	const u_char *name;
	size_t name_len;

	dentry = BPF_CORE_READ(path, dentry);
	vfsmnt = BPF_CORE_READ(path, mnt);
	mnt = container_of(vfsmnt, struct mount, mnt);
	mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

	size_t buf_off = HALF_PERCPU_ARRAY_SIZE - 1;

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {

    dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
    dentry_parent = BPF_CORE_READ(dentry, d_parent);

    if (dentry == dentry_mnt || dentry == dentry_parent) {
      if (dentry != dentry_mnt) {
        // We reached root, but not mount root - escaped?
        break;
      }
      if (mnt != mnt_parent) {
        // We reached root, but not global root - continue with mount point path
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
        vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
        continue;
      }
      // Global root - path fully parsed
      break;
    }

    // Add this dentry name to path
    name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
    name = BPF_CORE_READ(dentry, d_name.name);

    name_len = name_len + 1;
    // Is string buffer big enough for dentry name?
    if (name_len > buf_off) { break; }
    volatile size_t new_buff_offset = buf_off - name_len; // satisfy verifier
    ret = bpf_probe_read_kernel_str(
		&(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(new_buff_offset)]),// satisfy verifie
		name_len, name);

    if (ret < 0) { return ret; }

    if (ret > 1) {
		buf_off -= 1;                                    // remove null byte termination with slash sign
		buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
		out_buf->data[buf_off] = '/';
		buf_off -= ret - 1;
		buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
    } else {
		// If sz is 0 or 1 we have an error (path can't be null nor an empty string)
		break;
    }
    dentry = dentry_parent;
  }

  // Is string buffer big enough for slash?
  if (buf_off != 0) {
    // Add leading slash
    buf_off -= 1;
    buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
    out_buf->data[buf_off] = '/';
  }

	// Null terminate the path string
	out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
	*path_str = &out_buf->data[buf_off];

	if (append) {
		name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(append, d_name.len));
		name = BPF_CORE_READ(append, d_name.name);

		ret = bpf_probe_read_kernel_str(&(out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1]), name_len + 1, name);
	} else {
		out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1 - 1] = 0;
	}

	return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

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
    int ret = 0, findex =0;
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

	bpf_printk("denied files: %s\n", paths->path);
	bpf_printk("event files: %s\n", event->path);
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
    if (ret != 0) \
		bpf_perf_event_output((void *)ctx, &fileopen_events, BPF_F_CURRENT_CPU, &event, sizeof(event)); \
	if (ret > 0) ret = 0; \
    return ret;

#define PROG_CODE_A \
	int ret = 0; \
    struct file_open_audit_event event = {};\
    get_file_info(&event);\
    ret = get_path_perm(&event, dir, dentry);\
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
