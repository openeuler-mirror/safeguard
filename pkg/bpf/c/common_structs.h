#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ALLOW_ACCESS 0
#define AUDIT_EVENTS_RING_SIZE (4 * 4096)
#define TASK_COMM_LEN 16
#define NEW_UTS_LEN 64
#define NAME_MAX 255
#define DEV_LEN 64
#define LOOP_NAME 80
#define MAX_PATH_SIZE 4096 // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))

#define VERSION_5_10 KERNEL_VERSION(5,10,0)
#define NULL ((void *)0)

#define BPF_RING_BUF(name, size)        \
  struct                                \
  {                                     \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, size);          \
  } name SEC(".maps")

#define BPF_HASH(name, key_type, val_type, size) \
  struct                                         \
  {                                              \
    __uint(type, BPF_MAP_TYPE_HASH);             \
    __uint(max_entries, size);                   \
    __type(key, key_type);                       \
    __type(value, val_type);                     \
  } name SEC(".maps")

enum mode
{
  MODE_MONITOR,
  MODE_BLOCK
};

enum lsm_hook_point
{
  CONNECT,
  SENDMSG // Not implemented yet.
};

enum svrtarget
{
	TARGET_HOST,
	TARGET_CONTAINER
};

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

struct mount_audit_event {
    u64 cgroup;
    u32 pid;
    u32 uid;
    int ret;
    char nodename[NEW_UTS_LEN + 1];
    char task[TASK_COMM_LEN];
    char parent_task[TASK_COMM_LEN];
    unsigned char path[NAME_MAX];
};

struct mount_safeguard_config {
    u32 mode;
    u32 target;
};

struct network_safeguard_config
{
  enum mode mode;
  u32 target;
  int has_allow_command;
  int has_allow_uid;
};

struct buffer {
  u8 data[MAX_PERCPU_ARRAY_SIZE];
};

static inline int _is_host_mntns()
{
  struct task_struct *current_task;
  struct nsproxy *nsproxy;
  struct mnt_namespace *mnt_ns;
  unsigned int inum;

  current_task = (struct task_struct *)bpf_get_current_task();

  BPF_CORE_READ_INTO(&inum, current_task, nsproxy, mnt_ns, ns.inum);
  if (inum == 0xF0000000)
  {
    return true;
  }

  return false;
}

static inline int is_container()
{
  return !_is_host_mntns();
}

static inline int strcmp(const unsigned char *a, const unsigned char *b, size_t len)
{
  unsigned char c1, c2;
  size_t i;

  for (i=0; i<len; i++) {
    c1 = (unsigned char)a[i];
    c2 = (unsigned char)b[i];

    if (c1 != c2 || c1 == '\0' || c2 == '\0') {
      return 1;
    }
  }

  return 0;
}

static __always_inline int strlen(const unsigned char *s, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (s[i] == '\0')
			return i;
	}

	return i;
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
