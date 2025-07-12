#include "common_structs.h"
#include "restricted_network_structs.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

// 定义许可证信息
char license_info[] SEC("license") = "Dual BSD/GPL";

// 定义环形缓冲区和哈希表
BPF_RING_BUF(network_audit_logs, AUDIT_EVENTS_RING_SIZE);
BPF_HASH(net_security_policy_map, u32, struct network_safeguard_config, 256);

BPF_HASH(permitted_cmd_map, struct allowed_command_key, u32, 256);
BPF_HASH(blocked_cmd_map, struct denied_command_key, u32, 256);

BPF_HASH(permitted_user_map, struct allowed_uid_key, u32, 256);
BPF_HASH(blocked_user_map, struct denied_uid_key, u32, 256);

BPF_HASH(permitted_group_map, struct allowed_gid_key, u32, 256);
BPF_HASH(blocked_group_map, struct denied_gid_key, u32, 256);

// 定义 IPv4 和 IPv6 的 CIDR 黑白名单
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv4_trie_key);
  __type(value, char);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} restricted_ipv4_cidr SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv6_trie_key);
  __type(value, char);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} restricted_ipv6_cidr SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv4_trie_key);
  __type(value, char);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} permitted_ipv4_cidr SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 256);
  __type(key, struct ipv6_trie_key);
  __type(value, char);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} permitted_ipv6_cidr SEC(".maps");

// 记录 IPv4 网络事件
static inline void log_ipv4_activity(void *context, u64 cgroup_id, enum action act,
                                     enum lsm_hook_point hook, struct socket *socket_ptr,
                                     const struct sockaddr_in *dest_addr) {
  struct audit_event_ipv4 event_data;

  struct task_struct *current_process;
  struct uts_namespace *uts_namespace_ptr;
  struct nsproxy *namespace_proxy;
  current_process = (struct task_struct *)bpf_get_current_task();

  // 清空事件数据结构
  __builtin_memset(&event_data, 0, sizeof(event_data));
  // 读取节点名称
  BPF_CORE_READ_INTO(&event_data.hdr.nodename, current_process, nsproxy, uts_ns, name.nodename);
  event_data.hdr.cgroup = cgroup_id;
  event_data.hdr.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  event_data.hdr.type = BLOCKED_IPV4;
  bpf_get_current_comm(&event_data.hdr.task, sizeof(event_data.hdr.task));

  // 获取父进程信息
  struct task_struct *parent_process = BPF_CORE_READ(current_process, real_parent);
  bpf_probe_read_kernel_str(&event_data.hdr.parent_task, sizeof(event_data.hdr.parent_task),
                            &parent_process->comm);

  // 设置事件详细信息
  event_data.dport = __builtin_bswap16(dest_addr->sin_port);
  event_data.src = src_addr4(socket_ptr);
  event_data.dst = BPF_CORE_READ(dest_addr, sin_addr);
  event_data.operation = (u8)hook;
  event_data.action = (u8)act;
  event_data.sock_type = (u8)socket_ptr->type;

  // 输出到环形缓冲区
  bpf_ringbuf_output(&network_audit_logs, &event_data, sizeof(event_data), 0);
}

// 记录 IPv6 网络事件
static inline void log_ipv6_activity(void *context, u64 cgroup_id, enum action act,
                                     enum lsm_hook_point hook, struct socket *socket_ptr,
                                     const struct sockaddr_in6 *dest_addr) {
  struct audit_event_ipv6 event_data;

  struct task_struct *current_process;
  struct uts_namespace *uts_namespace_ptr;
  struct nsproxy *namespace_proxy;
  current_process = (struct task_struct *)bpf_get_current_task();

  // 清空事件数据结构
  __builtin_memset(&event_data, 0, sizeof(event_data));
  // 读取节点名称
  BPF_CORE_READ_INTO(&event_data.hdr.nodename, current_process, nsproxy, uts_ns, name.nodename);
  event_data.hdr.cgroup = cgroup_id;
  event_data.hdr.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  event_data.hdr.type = BLOCKED_IPV6;
  bpf_get_current_comm(&event_data.hdr.task, sizeof(event_data.hdr.task));

  // 获取父进程信息
  struct task_struct *parent_process = BPF_CORE_READ(current_process, real_parent);
  bpf_probe_read_kernel_str(&event_data.hdr.parent_task, sizeof(event_data.hdr.parent_task),
                            &parent_process->comm);

  // 设置事件详细信息
  event_data.dport = __builtin_bswap16(dest_addr->sin6_port);
  event_data.src = src_addr6(socket_ptr);
  event_data.dst = BPF_CORE_READ(dest_addr, sin6_addr);
  event_data.operation = (u8)hook;
  event_data.action = (u8)act;
  event_data.sock_type = (u8)socket_ptr->type;

  // 输出到环形缓冲区
  bpf_ringbuf_output(&network_audit_logs, &event_data, sizeof(event_data), 0);
}

// 检查 IPv4 目标端口是否为 0
static inline bool is_ipv4_port_zero(struct sockaddr_in *address) {
  return __builtin_bswap16(address->sin_port) == 0;
}

// 检查 IPv6 目标端口是否为 0
static inline bool is_ipv6_port_zero(struct sockaddr_in6 *address) {
  return __builtin_bswap16(address->sin6_port) == 0;
}

// 获取网络权限
static inline int evaluate_network_access(struct network_safeguard_config *policy, struct sockaddr *addr) {
  int connect_permission = -EPERM;
  int command_permission = -EPERM;
  int user_permission = -EPERM;
  int group_permission = -EPERM;

  struct sockaddr addr_copy;
  bpf_probe_read_kernel(&addr_copy, sizeof(struct sockaddr), addr);

  bool is_ipv6_addr = (addr_copy.sa_family == AF_INET6);
  bool is_ipv4_addr = (addr_copy.sa_family == AF_INET);

  if (!(is_ipv4_addr || is_ipv6_addr)) {
    return 0;
  }

  struct sockaddr_in *ipv4_addr;
  struct sockaddr_in6 *ipv6_addr;

  if (is_ipv6_addr) {
    ipv6_addr = (struct sockaddr_in6 *)&addr_copy;
  } else {
    ipv4_addr = (struct sockaddr_in *)&addr_copy;
  }

  // 如果目标端口为 0，则不进行审计
  if ((is_ipv6_addr && is_ipv6_port_zero(ipv6_addr)) ||
      (is_ipv4_addr && is_ipv4_port_zero(ipv4_addr))) {
    return 0;
  }

  union ip_trie_key trie_key = {.v4.prefixlen = 32, .v4.addr = ipv4_addr->sin_addr};
  if (is_ipv6_addr) {
    trie_key.v6.prefixlen = 128;
    trie_key.v6.addr = BPF_CORE_READ(ipv6_addr, sin6_addr);
  }

  // 初始化权限检查相关键
  struct allowed_command_key allowed_cmd_key;
  struct denied_command_key denied_cmd_key;
  struct allowed_uid_key allowed_user_key;
  struct denied_uid_key denied_user_key;
  struct allowed_gid_key allowed_group_key;
  struct denied_gid_key denied_group_key;

  bpf_get_current_comm(&allowed_cmd_key.comm, sizeof(allowed_cmd_key.comm));
  bpf_get_current_comm(&denied_cmd_key.comm, sizeof(denied_cmd_key.comm));

  allowed_user_key.uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
  denied_user_key.uid = (unsigned)(bpf_get_current_uid_gid() & 0xffffffff);
  allowed_group_key.gid = (unsigned)(bpf_get_current_uid_gid() >> 32);
  denied_group_key.gid = (unsigned)(bpf_get_current_uid_gid() >> 32);

  // 检查配置中的限制条件
  int cmd_restriction_enabled = 0;
  int user_restriction_enabled = 0;
  int group_restriction_enabled = 0;

  if (policy && policy->has_allow_command) {
    cmd_restriction_enabled = policy->has_allow_command;
  }
  if (policy && policy->has_allow_uid) {
    user_restriction_enabled = policy->has_allow_uid;
  }

  // 如果目标是容器，且当前不是容器环境，则直接放行
  if (policy && policy->target == TARGET_CONTAINER) {
    if (!is_container()) {
      return 0;
    }
  }

  // 检查 IP 地址是否在白名单中
  if ((is_ipv4_addr && bpf_map_lookup_elem(&permitted_ipv4_cidr, &trie_key.v4)) ||
      (is_ipv6_addr && bpf_map_lookup_elem(&permitted_ipv6_cidr, &trie_key.v6))) {
    connect_permission = 0;
  }

  // 检查用户是否在白名单中
  if (bpf_map_lookup_elem(&permitted_user_map, &allowed_user_key) ||
      user_restriction_enabled == 0) {
    user_permission = 0;
  }

  // 检查组是否在白名单中
  if (bpf_map_lookup_elem(&permitted_group_map, &allowed_group_key) ||
      group_restriction_enabled == 0) {
    group_permission = 0;
  }

  // 检查命令是否在白名单中
  if (bpf_map_lookup_elem(&permitted_cmd_map, &allowed_cmd_key) ||
      cmd_restriction_enabled == 0) {
    command_permission = 0;
  }

  // 检查命令是否在黑名单中
  if (bpf_map_lookup_elem(&blocked_cmd_map, &denied_cmd_key)) {
    command_permission = -EPERM;
  }

  // 检查用户是否在黑名单中
  if (bpf_map_lookup_elem(&blocked_user_map, &denied_user_key)) {
    user_permission = -EPERM;
  }

  // 检查组是否在黑名单中
  if (bpf_map_lookup_elem(&blocked_group_map, &denied_group_key)) {
    group_permission = -EPERM;
  }

  // 检查 IP 地址是否在黑名单中
  if ((is_ipv4_addr && bpf_map_lookup_elem(&restricted_ipv4_cidr, &trie_key.v4)) ||
      (is_ipv6_addr && bpf_map_lookup_elem(&restricted_ipv6_cidr, &trie_key.v6))) {
    connect_permission = -EPERM;
  }

  // 如果 IP 在黑名单中，但命令、用户或组在白名单中，则放行
  if (((is_ipv4_addr && bpf_map_lookup_elem(&restricted_ipv4_cidr, &trie_key.v4)) ||
       (is_ipv6_addr && bpf_map_lookup_elem(&restricted_ipv6_cidr, &trie_key.v6))) &&
      bpf_map_lookup_elem(&permitted_cmd_map, &allowed_cmd_key)) {
    connect_permission = 0;
  }

  if (((is_ipv4_addr && bpf_map_lookup_elem(&restricted_ipv4_cidr, &trie_key.v4)) ||
       (is_ipv6_addr && bpf_map_lookup_elem(&restricted_ipv6_cidr, &trie_key.v6))) &&
      bpf_map_lookup_elem(&permitted_user_map, &allowed_user_key)) {
    connect_permission = 0;
  }

  if (((is_ipv4_addr && bpf_map_lookup_elem(&restricted_ipv4_cidr, &trie_key.v4)) ||
       (is_ipv6_addr && bpf_map_lookup_elem(&restricted_ipv6_cidr, &trie_key.v6))) &&
      bpf_map_lookup_elem(&permitted_group_map, &allowed_group_key)) {
    connect_permission = 0;
  }

  // 综合判断是否允许访问
  int final_access = -EPERM;
  if (connect_permission == 0 && user_permission == 0 && group_permission == 0 &&
      command_permission == 0) {
    final_access = 0;
  }

  // 如果是监控模式，则始终放行
  if (policy && policy->mode == MODE_MONITOR) {
    return 0;
  }
  return final_access;
}

// 记录网络事件
static inline void record_network_events(struct network_safeguard_config *policy, int access_result,
                                         unsigned long long *context, struct socket *socket_ptr,
                                         struct sockaddr *addr) {
  unsigned short addr_family = BPF_CORE_READ(addr, sa_family);
  bool is_ipv6_addr = (addr_family == AF_INET6);
  bool is_ipv4_addr = (addr_family == AF_INET);

  u64 cgroup_id = bpf_get_current_cgroup_id();

  struct sockaddr_in *ipv4_addr;
  struct sockaddr_in6 *ipv6_addr;

  if (is_ipv6_addr) {
    ipv6_addr = (struct sockaddr_in6 *)addr;
  } else {
    ipv4_addr = (struct sockaddr_in *)addr;
  }

  // 如果访问被拒绝且处于阻止模式，则记录阻止事件
  if (access_result != 0 && policy && policy->mode == MODE_BLOCK) {
    if (is_ipv4_addr) {
      log_ipv4_activity((void *)context, cgroup_id, ACTION_BLOCK, CONNECT, socket_ptr, ipv4_addr);
    } else {
      log_ipv6_activity((void *)context, cgroup_id, ACTION_BLOCK, CONNECT, socket_ptr, ipv6_addr);
    }
  }

  // 如果处于监控模式，则记录监控事件
  if (policy && policy->mode == MODE_MONITOR) {
    if (is_ipv4_addr) {
      log_ipv4_activity((void *)context, cgroup_id, ACTION_MONITOR, CONNECT, socket_ptr, ipv4_addr);
    } else {
      log_ipv6_activity((void *)context, cgroup_id, ACTION_MONITOR, CONNECT, socket_ptr, ipv6_addr);
    }
  }
}

// LSM 钩子函数：处理 socket_connect
SEC("lsm/socket_connect")
int BPF_PROG(handle_socket_connect, struct socket *socket_ptr, struct sockaddr *addr, int addr_len) {
  u32 map_index = 0;
  struct network_safeguard_config *policy =
      (struct network_safeguard_config *)bpf_map_lookup_elem(&net_security_policy_map, &map_index);

  int access_result = evaluate_network_access(policy, addr);
  record_network_events(policy, access_result, ctx, socket_ptr, addr);
  return access_result;
}

// LSM 钩子函数：处理 socket_bind
SEC("lsm/socket_bind")
int BPF_PROG(handle_socket_bind, struct socket *socket_ptr, struct sockaddr *addr, int addr_len) {
  u32 map_index = 0;
  struct network_safeguard_config *policy =
      (struct network_safeguard_config *)bpf_map_lookup_elem(&net_security_policy_map, &map_index);

  int access_result = evaluate_network_access(policy, addr);
  record_network_events(policy, access_result, ctx, socket_ptr, addr);
  return access_result;
}