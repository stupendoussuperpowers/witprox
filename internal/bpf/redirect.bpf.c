#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2

struct conn_info {
	__u32 o_dst_ip;
	__u32 o_dst_port;
	__u32 pid;
	__u32 padding;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct conn_info);
} client_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u64);
	__type(value, struct conn_info);
} server_map SEC(".maps");

struct conn_tuple {
	__u32 saddr;
	__u32 daddr;
	__u32 sport;
	__u32 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct conn_tuple);
	__type(value, __u64);
} t_2_c SEC(".maps");

SEC("cgroup/connect4")
int redirect_connect4(struct bpf_sock_addr *ctx) {
	if (ctx->protocol != IPPROTO_TCP)
		return 1;

	__u32 o_dst_ip = ctx->user_ip4;
	__u32 o_dst_port = ctx->user_port;

	if (bpf_ntohl(o_dst_ip) == 0x74000001 && bpf_ntohs(o_dst_port) == 1230)
		return 1;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	struct pid *pid_struct = NULL;
	bpf_core_read(&pid_struct, sizeof(pid_struct), &task->thread_pid);
	if (!pid_struct)
		return 1;

	unsigned int level = 0;
	bpf_core_read(&level, sizeof(level), &pid_struct->level);

	struct upid upid_entry = {};
	bpf_core_read(&upid_entry, sizeof(upid_entry), &pid_struct->numbers[level]);

	int pid_ns = upid_entry.nr;

	struct conn_info val = {
		.o_dst_ip = o_dst_ip, 
		.o_dst_port = o_dst_port, 
		.pid = pid_ns, 
		.padding = 0,
	};
	// Get a socket cookie, store information about client process, original
	// destination.
	__u64 cookie = bpf_get_socket_cookie(ctx);
	bpf_map_update_elem(&client_map, &cookie, &val, BPF_ANY);

	// Rewrite destination to 127.0.0.1:1230
	ctx->user_ip4 = bpf_htonl(0x7f000001); // 127.0.0.1
	ctx->user_port = bpf_htons(1230);      // new port

	return 1;
}

SEC("sockops")
int track_conn(struct bpf_sock_ops *skops) {
	__u32 op = skops->op;

	// ACTIVE end is for the socket of the client that makes the connection.
	if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
		__u64 cookie = bpf_get_socket_cookie(skops);

		bpf_printk("Cookie: %d\n", cookie);

		struct conn_tuple tuple = {
		    .saddr = skops->local_ip4,
		    .daddr = skops->remote_ip4,
		    .sport = skops->local_port,
		    .dport = bpf_htons(1230),
		};

		// Match client cookie with a 4-tuple.
		bpf_map_update_elem(&t_2_c, &tuple, &cookie, BPF_ANY);
		bpf_printk("Updated t_2_c");
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
