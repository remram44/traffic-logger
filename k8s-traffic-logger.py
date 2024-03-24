from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
from collections import namedtuple, defaultdict

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(ipv4_send_bytes, u32);
BPF_HASH(ipv4_recv_bytes, u32);

BPF_HASH(ipv6_send_bytes, unsigned __int128);
BPF_HASH(ipv6_recv_bytes, unsigned __int128);

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

# output
exiting = False
while not exiting:
    try:
        sleep(10)
    except KeyboardInterrupt:
        exiting = True

    print()

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

    if ipv4_throughput:
        print("%-21s %6s %6s" % ("LADDR", "RX_KB", "TX_KB"))

    # output
    for k, (send_bytes, recv_bytes) in sorted(ipv4_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True):
        print("%-21s %6d %6d" % (
            k,
            int(recv_bytes / 1024),
            int(send_bytes / 1024),
        ))

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

    if ipv6_throughput:
        # more than 80 chars, sadly.
        print("\n%-32s %6s %6s" % ("LADDR6", "RX_KB", "TX_KB"))

    # output
    for k, (send_bytes, recv_bytes) in sorted(ipv6_throughput.items(),
                                              key=lambda kv: sum(kv[1]),
                                              reverse=True):
        print("%-32s %6d %6d" % (
            k,
            int(recv_bytes / 1024),
            int(send_bytes / 1024),
        ))
