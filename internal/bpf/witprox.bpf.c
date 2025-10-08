#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

SEC("sockops")
int track_conn(struct bpf_sock_ops *skops) {
	__u32 op = skops->op;

	// This is for the proxy that accepts the socket connection. 
	if (op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
		bpf_printk("Inside passive");
		__u64 server_cookie = bpf_get_socket_cookie(skops);

		if(skops->family != AF_INET)
			return 0;
		struct conn_tuple tuple = {
			.saddr = skops->remote_ip4,
			.daddr = skops->local_ip4,
			.sport = bpf_ntohl(skops->remote_port),
			.dport = bpf_ntohs(skops->local_port),
		};

		bpf_printk("saddr: %d | daddr: %d \n", tuple.saddr, tuple.daddr);
		bpf_printk("| sport: %d | dport: %d\n", tuple.sport, tuple.dport);

		// Use the 4-tuple to fetch the client's socket cookie
		__u64 *client_cookie = bpf_map_lookup_elem(&t_2_c, &tuple);
		bpf_printk("client_cookie: %p\n", client_cookie);
		if (!client_cookie) {
			bpf_printk("passive_est: no client cookie");
			return 0;
		}
		
		// Use client cookie to get orig_dst, orig_port, pid.
		struct conn_info *info = bpf_map_lookup_elem(&client_map, client_cookie);
		if(!info) {
			bpf_printk("passive_est: no info");
			return 0;
		}

		bpf_map_update_elem(&server_map, &server_cookie, info, BPF_ANY);

		bpf_map_delete_elem(&client_map, client_cookie);
		bpf_map_delete_elem(&t_2_c, &tuple);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
