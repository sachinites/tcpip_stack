import gdb
import struct
import socket


def ipv4(addr):
    return socket.inet_ntop(socket.AF_INET, addr)


class DecodeIPv4Pkt(gdb.Command):
    """Decode IPv4 packet followed by ICMP or UDP"""

    def __init__(self):
        super(DecodeIPv4Pkt, self).__init__("decode_ipv4_pkt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):

        pkt = int(gdb.parse_and_eval(arg))
        inferior = gdb.selected_inferior()

        # ---- IPv4 HEADER ----
        ipv4_hdr = inferior.read_memory(pkt, 20)

        ver_ihl, tos, tot_len, ident, frag, ttl, proto, csum, src, dst = \
            struct.unpack("!BBHHHBBHII", ipv4_hdr)

        version = ver_ihl >> 4
        ihl = (ver_ihl & 0xF) * 4

        print("\n===== IPv4 HEADER =====")
        print("Version     :", version)
        print("Header Len  :", ihl)
        print("Total Len   :", tot_len)
        print("TTL         :", ttl)
        print("Protocol    :", proto)
        print("Src IPv4    :", ipv4(struct.pack("!I", src)))
        print("Dst IPv4    :", ipv4(struct.pack("!I", dst)))

        offset = ihl

        # ---- ICMP ----
        if proto == 1:

            icmp_hdr = inferior.read_memory(pkt + offset, 8)

            icmp_type, icmp_code, checksum, ident, seq = \
                struct.unpack("!BBHHH", icmp_hdr)

            print("\n===== ICMP HEADER =====")
            print("Type        :", icmp_type)
            print("Code        :", icmp_code)
            print("Checksum    :", hex(checksum))
            print("Identifier  :", ident)
            print("Sequence    :", seq)

        # ---- UDP ----
        elif proto == 17:

            udp_hdr = inferior.read_memory(pkt + offset, 8)

            src_port, dst_port, length, checksum = \
                struct.unpack("!HHHH", udp_hdr)

            print("\n===== UDP HEADER =====")
            print("Src Port    :", src_port)
            print("Dst Port    :", dst_port)
            print("Length      :", length)
            print("Checksum    :", hex(checksum))

        else:
            print("\nUnsupported L4 protocol:", proto)


DecodeIPv4Pkt()