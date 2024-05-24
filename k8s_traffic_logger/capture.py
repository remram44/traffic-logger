from bcc import BPF
from collections import defaultdict
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(ipv4_send_bytes, u32);
BPF_HASH(ipv4_recv_bytes, u32);

BPF_HASH(ipv6_send_bytes, unsigned __int128);
BPF_HASH(ipv6_recv_bytes, unsigned __int128);

BPF_HASH(ipv4_udp_recv_pending, u64, u32);
BPF_HASH(ipv6_udp_recv_pending, u64, unsigned __int128);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        u32 saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_send_bytes.increment(saddr, size);

    } else if (family == AF_INET6) {
        unsigned __int128 saddr;
        bpf_probe_read_kernel(&saddr, sizeof(saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        ipv6_send_bytes.increment(saddr, size);
    }
    // else drop

    return 0;
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    u16 family = sk->__sk_common.skc_family;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        u32 saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_recv_bytes.increment(saddr, copied);

    } else if (family == AF_INET6) {
        unsigned __int128 saddr;
        bpf_probe_read_kernel(&saddr, sizeof(saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        ipv6_recv_bytes.increment(saddr, copied);
    }
    // else drop

    return 0;
}

int udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t len)
{
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        u32 saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_send_bytes.increment(saddr, len);

    } else if (family == AF_INET6) {
        unsigned __int128 saddr;
        bpf_probe_read_kernel(&saddr, sizeof(saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        ipv6_send_bytes.increment(saddr, len);
    }
    // else drop

    return 0;
}

int udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg,
    size_t len, int flags, int *addr_len)
{
    u16 family = sk->__sk_common.skc_family;

    if (len <= 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (family == AF_INET) {
        u32 saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_udp_recv_pending.update(&pid_tgid, &saddr);

    } else if (family == AF_INET6) {
        unsigned __int128 saddr;
        bpf_probe_read_kernel(&saddr, sizeof(saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        ipv6_udp_recv_pending.update(&pid_tgid, &saddr);
    }
    // else drop

    return 0;
}

int ret_udp_recvmsg(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    if (ret > 0) {
        u32 *saddr = ipv4_udp_recv_pending.lookup(&pid_tgid);
        if (saddr) {
            ipv4_recv_bytes.increment(*saddr, ret);
        } else {
            unsigned __int128 *saddr6 = ipv6_udp_recv_pending.lookup(&pid_tgid);
            if (saddr6) {
                ipv6_recv_bytes.increment(*saddr6, ret);
            }
        }
    }
    ipv4_udp_recv_pending.delete(&pid_tgid);
    ipv6_udp_recv_pending.delete(&pid_tgid);

    return 0;
}
"""


def get_ipv4_key(k):
    return inet_ntop(AF_INET, pack("I", k.value))

def get_ipv6_key(k):
    return inet_ntop(AF_INET6, k)


# initialize BPF
b = BPF(text=bpf_text)
ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]
ipv6_send_bytes = b["ipv6_send_bytes"]
ipv6_recv_bytes = b["ipv6_recv_bytes"]

b.attach_kprobe(event="udp_sendmsg", fn_name="udp_sendmsg")
b.attach_kprobe(event="udpv6_sendmsg", fn_name="udp_sendmsg")
b.attach_kprobe(event="udp_recvmsg", fn_name="udp_recvmsg")
b.attach_kprobe(event="udpv6_recvmsg", fn_name="udp_recvmsg")
b.attach_kretprobe(event="udp_recvmsg", fn_name="ret_udp_recvmsg")
b.attach_kretprobe(event="udpv6_recvmsg", fn_name="ret_udp_recvmsg")


def get_traffic_counters_ipv4():
    # IPv4: build dict of all seen keys
    ipv4_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv4_send_bytes.items():
        key = get_ipv4_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send_bytes.clear()

    for k, v in ipv4_recv_bytes.items():
        key = get_ipv4_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv_bytes.clear()

    return ipv4_throughput


def get_traffic_counters_ipv6():
    # IPv6: build dict of all seen keys
    ipv6_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv6_send_bytes.items():
        key = get_ipv6_key(k)
        ipv6_throughput[key][0] = v.value
    ipv6_send_bytes.clear()

    for k, v in ipv6_recv_bytes.items():
        key = get_ipv6_key(k)
        ipv6_throughput[key][1] = v.value
    ipv6_recv_bytes.clear()

    return ipv6_throughput
