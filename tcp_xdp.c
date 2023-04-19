#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct tcp_conn_key {
	unsigned int saddr;
	unsigned int daddr;
	unsigned short source;
	unsigned short dest;
};

struct tcp_options {
	unsigned int mss;
};

struct tcp_conn {
	struct tcp_conn_key key;
	unsigned int seq;
	int state;
	unsigned int mss;
};

#if 0
struct bpf_map_def SEC("maps") tcp_conn_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcp_conn_key),
	.value_size = sizeof(struct tcp_conn),
	.max_entries = 1000,
};
#else
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000);
	__type(key, struct tcp_conn_key);
	__type(value, struct tcp_conn);
} tcp_conn_map SEC(".maps");
#endif

int build_and_send_tcp(struct xdp_md *ctx, struct tcphdr *ntcp)
{
	return XDP_PASS;
}

int new_tcp_connect(struct xdp_md *ctx, struct tcphdr *tcp, struct tcp_conn_key *key)
{
	bpf_printk("new tcp connect port %u with %u\n", key->dest, key->source);

	if (tcp->syn) {
		// deal with TCP options here

		struct tcp_conn conn = {
			.key = *key,
			.seq = bpf_ntohl(tcp->seq),
		};

		bpf_map_update_elem(&tcp_conn_map, key, &conn, BPF_ANY);
	}

	return XDP_PASS;
}

int process_tcp(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr *tcp)
{
	struct tcp_conn_key key = {
		.saddr = bpf_ntohl(ip->saddr),
		.daddr = bpf_ntohl(ip->daddr),
		.source = bpf_ntohs(tcp->source),
		.dest = bpf_ntohs(tcp->dest),
	};

	struct tcp_conn *conn = bpf_map_lookup_elem(&tcp_conn_map, &key);
	if (conn == NULL) {
		return new_tcp_connect(ctx, tcp, &key);
	}

	return XDP_PASS;
}

struct tlhdr {
	unsigned char type;
	unsigned char len;
};

void parse_tcp_option(struct tlhdr *tl, void *end, struct tcp_options *option)
{
	unsigned char type = tl->type;
	unsigned char len = tl->len;

	switch(type) {
		case 2: /* MSS */
			if ((void *)(tl + 1) + 4 < end) {
			}
	}
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    if (eth->h_proto != __bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > (struct iphdr *)data_end) {
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > (struct tcphdr *)data_end) {
        return XDP_DROP;
    }

    void *opt = tcp + 1;
    void *opt_end = (void *)tcp + tcp->doff * 4;

    if (opt_end > data_end) {
	    return XDP_DROP;
    }

    struct tcp_options options;

    for (int i = 0; i < 256; i++) {
	struct mss {
		unsigned char d[2];
	} *mss;

	    if (opt + 2 >=  opt_end || opt + 2 >= data_end) {
		    break;
	    }

	    struct tlhdr *tl = opt;
	    unsigned char type = tl->type;
	    unsigned char len = tl->len;
	    unsigned char *d = (unsigned char *)(tl + 1);

	    opt += 2;
	    switch(type) {
		    case 2: /* MSS , len is 2 */
			 mss = tl + 1;
			if (mss + 1 > data_end)
				break;

			options.mss = (d[0] << 8) + d[1];
			bpf_printk("mss = %lu\n", options.mss);
			break;
	    }


    }
    // we only deal with tcp port 8080 now
    if (bpf_ntohs(tcp->dest) != 8080) {
	    return XDP_PASS;
    }

    return process_tcp(ctx, ip, tcp);
}

char __license[] SEC("license") = "GPL";
