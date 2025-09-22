#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} blocked_port SEC(".maps");

SEC("cgroup/connect4")
int block_port(struct bpf_sock_addr *ctx) {
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&blocked_port, &key);
    if (!port)
        return 1; 

    if (bpf_ntohs(ctx->user_port) == *port)
        return 0; 
    return 1; 
}

char _license[] SEC("license") = "GPL";
