import gdb
import struct
import socket


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_VLAN = 0x8100

ARP_HW_ETHERNET = 1
ARP_OP_REQUEST  = 1
ARP_OP_REPLY    = 2


def mac_str(mac_bytes):
    return ':'.join(format(b, '02x') for b in bytearray(mac_bytes))


def ipv4(addr):
    return socket.inet_ntop(socket.AF_INET, addr)


def decode_arp(inferior, pkt, offset):
    # ARP fixed header: 8 bytes
    # htype(2) ptype(2) hlen(1) plen(1) oper(2)
    # followed by: sha(hlen) spa(plen) tha(hlen) tpa(plen)
    # For Ethernet/IPv4: hlen=6, plen=4  => total 28 bytes
    arp_hdr = inferior.read_memory(pkt + offset, 8)
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", bytes(arp_hdr))

    op_str = {ARP_OP_REQUEST: "REQUEST", ARP_OP_REPLY: "REPLY"}.get(oper, "UNKNOWN")

    print("\n===== ARP HEADER =====")
    print("HW Type     :", "Ethernet" if htype == ARP_HW_ETHERNET else hex(htype))
    print("Proto Type  :", hex(ptype))
    print("HW Addr Len :", hlen)
    print("Proto Len   :", plen)
    print("Operation   : {} ({})".format(oper, op_str))

    payload_offset = offset + 8
    payload_len = 2 * hlen + 2 * plen
    payload = inferior.read_memory(pkt + payload_offset, payload_len)

    pos = 0
    sha = bytes(payload[pos: pos + hlen]); pos += hlen
    spa = bytes(payload[pos: pos + plen]); pos += plen
    tha = bytes(payload[pos: pos + hlen]); pos += hlen
    tpa = bytes(payload[pos: pos + plen])

    if hlen == 6:
        print("Sender MAC  :", mac_str(sha))
        print("Target MAC  :", mac_str(tha))
    else:
        print("Sender HW   :", sha.hex())
        print("Target HW   :", tha.hex())

    if plen == 4:
        print("Sender IP   :", ipv4(spa))
        print("Target IP   :", ipv4(tpa))
    else:
        print("Sender Proto:", spa.hex())
        print("Target Proto:", tpa.hex())


def decode_ipv4(inferior, pkt, offset):
    ipv4_hdr = inferior.read_memory(pkt + offset, 20)

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

    l4_offset = offset + ihl

    # ---- ICMP ----
    if proto == 1:
        icmp_hdr = inferior.read_memory(pkt + l4_offset, 8)
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
        udp_hdr = inferior.read_memory(pkt + l4_offset, 8)
        src_port, dst_port, length, checksum = \
            struct.unpack("!HHHH", udp_hdr)

        print("\n===== UDP HEADER =====")
        print("Src Port    :", src_port)
        print("Dst Port    :", dst_port)
        print("Length      :", length)
        print("Checksum    :", hex(checksum))

    else:
        print("\nUnsupported L4 protocol:", proto)


class DecodeEthPkt(gdb.Command):
    """Decode packet starting from Ethernet header (optionally VLAN-tagged), followed by IPv4/ICMP/UDP.
    Usage: decode_eth_pkt <pkt_ptr>"""

    def __init__(self):
        super(DecodeEthPkt, self).__init__("decode_eth_pkt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        pkt = int(gdb.parse_and_eval(arg))
        inferior = gdb.selected_inferior()

        # ---- ETHERNET HEADER (14 bytes) ----
        eth_hdr = inferior.read_memory(pkt, 14)
        dst_mac  = eth_hdr[0:6]
        src_mac  = eth_hdr[6:12]
        ethertype = struct.unpack("!H", bytes(eth_hdr[12:14]))[0]

        print("\n===== ETHERNET HEADER =====")
        print("Dst MAC     :", mac_str(dst_mac))
        print("Src MAC     :", mac_str(src_mac))
        print("EtherType   :", hex(ethertype))

        offset = 14

        # ---- 802.1Q VLAN TAG (optional, 4 bytes) ----
        if ethertype == ETHERTYPE_VLAN:
            vlan_hdr = inferior.read_memory(pkt + offset, 4)
            tci, ethertype = struct.unpack("!HH", bytes(vlan_hdr))
            pcp = (tci >> 13) & 0x7
            dei = (tci >> 12) & 0x1
            vid =  tci        & 0xFFF

            print("\n===== VLAN TAG (802.1Q) =====")
            print("PCP         :", pcp)
            print("DEI         :", dei)
            print("VLAN ID     :", vid)
            print("Inner EType :", hex(ethertype))

            offset += 4

        # ---- L3 ----
        if ethertype == ETHERTYPE_IPV4:
            decode_ipv4(inferior, pkt, offset)
        elif ethertype == ETHERTYPE_ARP:
            decode_arp(inferior, pkt, offset)
        else:
            print("\nUnsupported EtherType:", hex(ethertype))


class DecodeIPv4Pkt(gdb.Command):
    """Decode IPv4 packet followed by ICMP or UDP (no Ethernet header).
    Usage: decode_ipv4_pkt <pkt_ptr>"""

    def __init__(self):
        super(DecodeIPv4Pkt, self).__init__("decode_ipv4_pkt", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        pkt = int(gdb.parse_and_eval(arg))
        inferior = gdb.selected_inferior()
        decode_ipv4(inferior, pkt, 0)


DecodeEthPkt()
DecodeIPv4Pkt()
