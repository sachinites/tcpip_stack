import gdb
import struct
import socket

def ipv6(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)

def ipv4(addr):
    return socket.inet_ntop(socket.AF_INET, addr)

class DecodeIPv6Pkt(gdb.Command):
    """Decode packet containing IPv6 + SRH + IPv4 + ICMP"""

    def __init__(self):
        super(DecodeIPv6Pkt, self).__init__("decode_ipv6_pkt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):

        pkt = int(gdb.parse_and_eval(arg))
        inferior = gdb.selected_inferior()

        # ---- IPv6 HEADER (40 bytes) ----
        ipv6_hdr = inferior.read_memory(pkt, 40)

        vtcfl, payload_len, next_hdr, hop_limit = struct.unpack("!IHBB", ipv6_hdr[:8])
        src = ipv6(ipv6_hdr[8:24])
        dst = ipv6(ipv6_hdr[24:40])

        print("\n===== IPv6 HEADER =====")
        print("Next Header :", next_hdr)
        print("Hop Limit   :", hop_limit)
        print("Src IPv6    :", src)
        print("Dst IPv6    :", dst)

        offset = 40

        # ---- SRH HEADER ----
        srh = inferior.read_memory(pkt + offset, 8)

        next_hdr, hdr_ext_len, routing_type, segments_left = struct.unpack("!BBBB", srh[:4])
        first_segment, flags, tag = struct.unpack("!BBH", srh[4:8])

        print("\n===== SRH HEADER =====")
        print("Next Header    :", next_hdr)
        print("Hdr Ext Len    :", hdr_ext_len)
        print("Segments Left  :", segments_left)
        print("First Segment  :", first_segment)

        srh_len = (hdr_ext_len + 1) * 8
        offset += srh_len

        # ---- IPv4 HEADER ----
        ipv4_hdr = inferior.read_memory(pkt + offset, 20)

        ver_ihl, tos, tot_len, ident, frag, ttl, proto, csum, src, dst = struct.unpack("!BBHHHBBHII", ipv4_hdr)

        ihl = (ver_ihl & 0x0F) * 4

        print("\n===== IPv4 HEADER =====")
        print("Protocol :", proto)
        print("TTL      :", ttl)
        print("Src IPv4 :", ipv4(struct.pack("!I", src)))
        print("Dst IPv4 :", ipv4(struct.pack("!I", dst)))

        offset += ihl

        # ---- ICMP HEADER ----
        icmp_hdr = inferior.read_memory(pkt + offset, 8)

        icmp_type, icmp_code, checksum = struct.unpack("!BBH", icmp_hdr[:4])

        print("\n===== ICMP HEADER =====")
        print("Type     :", icmp_type)
        print("Code     :", icmp_code)
        print("Checksum :", hex(checksum))


DecodeIPv6Pkt()