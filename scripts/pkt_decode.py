"""
pkt_decode.py — Unified GDB packet decoder
===========================================

Full-packet commands (walk the entire header chain):
  decode_pkt        <ptr>   auto-detect starting header (Eth or bare L3)
  decode_eth        <ptr>   start at Ethernet (tagged / QinQ / untagged)
  decode_eth_pkt    <ptr>   alias for decode_eth
  decode_ipv4_pkt   <ptr>   start at IPv4 header
  decode_ipv6_pkt   <ptr>   start at IPv6 header

Individual-header commands (decode only that header, no chain-walking):
  decode_hdr_eth    <ptr>   Ethernet + VLAN tags
  decode_hdr_ipv4   <ptr>   IPv4
  decode_hdr_ipv6   <ptr>   IPv6
  decode_hdr_srh    <ptr>   SRv6 Segment Routing Header
  decode_hdr_arp    <ptr>   ARP
  decode_hdr_icmp   <ptr>   ICMP / ICMPv6
  decode_hdr_udp    <ptr>   UDP
  decode_hdr_tcp    <ptr>   TCP

Supported packet combinations:
  Ethernet [802.1Q] [802.1ad/QinQ] + ARP
  Ethernet [VLAN]                  + IPv4 + ICMP | UDP | TCP
  Ethernet [VLAN]                  + IPv6 [SRH [IPv4 | IPv6]] + ICMP | UDP | TCP
  Bare IPv4                        + ICMP | UDP | TCP
  Bare IPv6       [SRH [IPv4]]     + ICMP | UDP | TCP

Usage example:
  (gdb) source scripts/pkt_decode.py
  (gdb) decode_pkt        pkt_block->pkt
  (gdb) decode_eth        pkt_block->pkt
  (gdb) decode_hdr_ipv4   some_ip_ptr
"""

import gdb
import struct
import socket

# ─────────────────────────────────────────────────────────────────────────────
# Protocol constants  (match protoIds.h / l2_hdrs.h)
# ─────────────────────────────────────────────────────────────────────────────

ETH_TYPE_IPv4        = 0x0800
ETH_TYPE_ARP         = 0x0806
ETH_TYPE_IPv6        = 0x86DD
ETH_TYPE_VLAN_8021Q  = 0x8100
ETH_TYPE_VLAN_8021AD = 0x88A8

IP_PROTO_ICMP   = 1
IP_PROTO_TCP    = 6
IP_PROTO_UDP    = 17
IP_PROTO_IPv6   = 41   # IPv6-in-IPv4
IP_PROTO_SRH    = 43   # Routing header (SRv6)
IP_PROTO_ICMPv6 = 58
IP_PROTO_IPv4   = 4    # IPv4-in-IPv6 (SRv6 endpoint decap)

ARP_OP_REQUEST  = 1
ARP_OP_REPLY    = 2

PKT_READ_SIZE = 2048   # matches MAX_PACKET_BUFFER_SIZE

# ─────────────────────────────────────────────────────────────────────────────
# Formatters
# ─────────────────────────────────────────────────────────────────────────────

def _mac(raw):
    return ":".join("%02x" % b for b in bytearray(raw))

def _ip4(raw):
    return socket.inet_ntop(socket.AF_INET, bytes(raw))

def _ip6(raw):
    return socket.inet_ntop(socket.AF_INET6, bytes(raw))

def _ip4_int(n):
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", n))

def _frag_field(frag):
    flags  = (frag >> 13) & 0x7
    offset =  frag        & 0x1FFF
    names  = []
    if flags & 0x2: names.append("DF")
    if flags & 0x1: names.append("MF")
    return "flags=0x%x(%s) offset=%d" % (flags, "|".join(names) if names else "-", offset)

def _tcp_flags(raw_flags):
    bits = [("FIN",0x001),("SYN",0x002),("RST",0x004),
            ("PSH",0x008),("ACK",0x010),("URG",0x020)]
    active = [n for n, m in bits if raw_flags & m]
    return "|".join(active) if active else "-"

# ─────────────────────────────────────────────────────────────────────────────
# Per-header parsers
#
# Convention:
#   parse_*(mem, offset) -> (next_proto, new_offset)
#   next_proto is the EtherType / IP-protocol for the immediately following
#   header, or None when there is nothing meaningful to chain.
# ─────────────────────────────────────────────────────────────────────────────

def parse_eth(mem, offset):
    """Ethernet II with optional 802.1Q / QinQ tags."""
    dst = mem[offset:offset+6]
    src = mem[offset+6:offset+12]
    etype, = struct.unpack("!H", mem[offset+12:offset+14])
    offset += 14

    print("\n===== ETHERNET HEADER =====")
    print("Dst MAC      :", _mac(dst))
    print("Src MAC      :", _mac(src))

    depth = 0
    while etype in (ETH_TYPE_VLAN_8021Q, ETH_TYPE_VLAN_8021AD):
        tci, inner = struct.unpack("!HH", mem[offset:offset+4])
        pcp = (tci >> 13) & 0x7
        dei = (tci >> 12) & 0x1
        vid =  tci        & 0xFFF
        tag_name = "802.1Q" if etype == ETH_TYPE_VLAN_8021Q else "802.1ad(QinQ)"
        label    = "VLAN Tag" if depth == 0 else "Inner VLAN Tag"
        print("%-14s : %s  PCP=%d  DEI=%d  VID=%d" % (label, tag_name, pcp, dei, vid))
        etype   = inner
        offset += 4
        depth  += 1

    print("EtherType    : 0x%04x" % etype)
    return etype, offset


def parse_arp(mem, offset):
    """ARP header for any hardware/protocol combination."""
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", mem[offset:offset+8])
    op_str = {ARP_OP_REQUEST: "REQUEST", ARP_OP_REPLY: "REPLY"}.get(oper, "UNKNOWN(%d)" % oper)

    print("\n===== ARP HEADER =====")
    print("HW Type      :", "Ethernet(1)" if htype == 1 else hex(htype))
    print("Proto Type   :", hex(ptype))
    print("HW Addr Len  :", hlen)
    print("Proto Len    :", plen)
    print("Operation    :", op_str)

    pos = offset + 8
    sha = mem[pos:pos+hlen]; pos += hlen
    spa = mem[pos:pos+plen]; pos += plen
    tha = mem[pos:pos+hlen]; pos += hlen
    tpa = mem[pos:pos+plen]; pos += plen

    print("Sender MAC   :", _mac(sha) if hlen == 6 else bytes(sha).hex())
    print("Target MAC   :", _mac(tha) if hlen == 6 else bytes(tha).hex())
    print("Sender IP    :", _ip4(spa) if plen == 4 else bytes(spa).hex())
    print("Target IP    :", _ip4(tpa) if plen == 4 else bytes(tpa).hex())

    return None, pos


def parse_ipv4(mem, offset):
    """IPv4 header (20 bytes fixed; IHL used to skip options)."""
    ver_ihl, tos, tot_len, ident, frag, ttl, proto, csum, src, dst = \
        struct.unpack("!BBHHHBBHII", mem[offset:offset+20])
    ihl = (ver_ihl & 0xF) * 4

    print("\n===== IPv4 HEADER =====")
    print("Version      :", (ver_ihl >> 4) & 0xF)
    print("IHL          :", ihl, "(bytes)")
    print("TOS/DSCP     :", "0x%02x" % tos)
    print("Total Len    :", tot_len)
    print("Ident        :", "0x%04x" % ident)
    print("Flags/Frag   :", _frag_field(frag))
    print("TTL          :", ttl)
    print("Protocol     :", proto)
    print("Checksum     :", hex(csum))
    print("Src IPv4     :", _ip4_int(src))
    print("Dst IPv4     :", _ip4_int(dst))

    return proto, offset + ihl


def parse_ipv6(mem, offset):
    """IPv6 fixed header (40 bytes)."""
    vtcfl, plen, next_hdr, hop = struct.unpack("!IHBB", mem[offset:offset+8])
    src = _ip6(mem[offset+8:offset+24])
    dst = _ip6(mem[offset+24:offset+40])

    print("\n===== IPv6 HEADER =====")
    print("Version      :", (vtcfl >> 28) & 0xF)
    print("Traffic Cls  :", "0x%02x" % ((vtcfl >> 20) & 0xFF))
    print("Flow Label   :", "0x%05x" % (vtcfl & 0xFFFFF))
    print("Payload Len  :", plen)
    print("Next Header  :", next_hdr)
    print("Hop Limit    :", hop)
    print("Src IPv6     :", src)
    print("Dst IPv6     :", dst)

    return next_hdr, offset + 40


def parse_srh(mem, offset):
    """SRv6 Segment Routing Header.

    NOTE: hdrlen in this codebase is the total SRH byte count
    (sizeof(srh_hdr_t) + n*16), NOT the RFC 8754 '8-octet units
    excluding first 8 bytes' encoding.  Used directly as byte offset.
    """
    next_hdr, hdrlen, rtype, segs_left = struct.unpack("!BBBB", mem[offset:offset+4])
    last_entry, flags, tag             = struct.unpack("!BBH",  mem[offset+4:offset+8])

    print("\n===== SRH HEADER =====")
    print("Next Header  :", next_hdr)
    print("Hdr Len      :", hdrlen, "(bytes, total SRH)")
    print("Routing Type :", rtype)
    print("Segs Left    :", segs_left)
    print("Last Entry   :", last_entry)
    print("Flags        :", "0x%02x" % flags)
    print("Tag          :", tag)

    seg_base = offset + 8
    for i in range(last_entry + 1):
        seg = mem[seg_base + i*16 : seg_base + i*16 + 16]
        print("Segment[%d]   : %s" % (i, _ip6(seg)))

    return next_hdr, offset + hdrlen


def parse_icmp(mem, offset):
    """ICMP / ICMPv6 header (8 bytes; echo fields shown for type 0/8/128/129)."""
    icmp_type, icmp_code, checksum, word4 = struct.unpack("!BBHi", mem[offset:offset+8])
    ident = (word4 >> 16) & 0xFFFF
    seq   =  word4        & 0xFFFF

    print("\n===== ICMP HEADER =====")
    print("Type         :", icmp_type)
    print("Code         :", icmp_code)
    print("Checksum     :", hex(checksum & 0xFFFF))
    if icmp_type in (0, 8, 128, 129):   # echo reply/request, ICMPv6 echo
        print("Identifier   :", ident)
        print("Sequence     :", seq)

    return None, offset + 8


def parse_udp(mem, offset):
    """UDP header (8 bytes)."""
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", mem[offset:offset+8])

    print("\n===== UDP HEADER =====")
    print("Src Port     :", src_port)
    print("Dst Port     :", dst_port)
    print("Length       :", length)
    print("Checksum     :", hex(checksum))

    return None, offset + 8


def parse_tcp(mem, offset):
    """TCP header (20 bytes fixed; data-offset used to skip options)."""
    src_port, dst_port, seq, ack, doff_flags, window, checksum, urg = \
        struct.unpack("!HHIIHHHH", mem[offset:offset+20])

    data_offset = ((doff_flags >> 12) & 0xF) * 4
    flags       =   doff_flags        & 0x1FF

    print("\n===== TCP HEADER =====")
    print("Src Port     :", src_port)
    print("Dst Port     :", dst_port)
    print("Seq          :", seq)
    print("Ack          :", ack)
    print("Data Offset  :", data_offset, "(bytes)")
    print("Flags        :", _tcp_flags(flags))
    print("Window       :", window)
    print("Checksum     :", hex(checksum))
    print("Urgent       :", urg)

    return None, offset + data_offset


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch_l4(mem, offset, proto):
    if   proto == IP_PROTO_ICMP:   parse_icmp(mem, offset)
    elif proto == IP_PROTO_ICMPv6: parse_icmp(mem, offset)
    elif proto == IP_PROTO_UDP:    parse_udp (mem, offset)
    elif proto == IP_PROTO_TCP:    parse_tcp (mem, offset)
    else:
        print("\n[IP protocol %d — no decoder implemented]" % proto)


def _dispatch_ipv6_chain(mem, offset, next_hdr):
    """Walk IPv6 extension headers then hand off to L4 (or inner IP)."""
    if next_hdr == IP_PROTO_SRH:
        next_hdr, offset = parse_srh(mem, offset)

    if next_hdr == IP_PROTO_IPv4:               # SRv6 endpoint decap → inner IPv4
        proto, offset = parse_ipv4(mem, offset)
        _dispatch_l4(mem, offset, proto)
    elif next_hdr == IP_PROTO_IPv6:             # tunnelled IPv6
        nh, offset = parse_ipv6(mem, offset)
        _dispatch_ipv6_chain(mem, offset, nh)
    else:
        _dispatch_l4(mem, offset, next_hdr)


def _dispatch_l3(mem, offset, etype):
    """Dispatch to L3 decoder then walk the chain."""
    if   etype == ETH_TYPE_IPv4:
        proto, offset = parse_ipv4(mem, offset)
        _dispatch_l4(mem, offset, proto)
    elif etype == ETH_TYPE_IPv6:
        nh, offset = parse_ipv6(mem, offset)
        _dispatch_ipv6_chain(mem, offset, nh)
    elif etype == ETH_TYPE_ARP:
        parse_arp(mem, offset)
    else:
        print("\n[EtherType 0x%04x — no decoder implemented]" % etype)


def _read_mem(pkt_addr):
    return gdb.selected_inferior().read_memory(pkt_addr, PKT_READ_SIZE)


def _sniff_start(mem):
    """Return (has_eth, ethertype).
    Peeks at bytes 12-13 for a known EtherType (Ethernet frame),
    otherwise sniffs the IP version nibble of byte 0."""
    KNOWN = {ETH_TYPE_IPv4, ETH_TYPE_IPv6, ETH_TYPE_VLAN_8021Q, ETH_TYPE_VLAN_8021AD}
    peek, = struct.unpack("!H", mem[12:14])
    if peek in KNOWN:
        return True, peek
    version = (bytearray(mem[0:1])[0] >> 4) & 0xF
    return False, (ETH_TYPE_IPv6 if version == 6 else ETH_TYPE_IPv4)


# ─────────────────────────────────────────────────────────────────────────────
# GDB command base class  (reduces boilerplate)
# ─────────────────────────────────────────────────────────────────────────────

class _PktCmd(gdb.Command):
    def __init__(self, name, doc):
        self.__doc__ = doc
        super(_PktCmd, self).__init__(name, gdb.COMMAND_USER)

    def _mem(self, arg):
        return _read_mem(int(gdb.parse_and_eval(arg)))


# ─────────────────────────────────────────────────────────────────────────────
# Full-packet walk commands
# ─────────────────────────────────────────────────────────────────────────────

class _DecodePkt(_PktCmd):
    """decode_pkt <ptr>  — auto-detect starting header and walk full chain"""
    def __init__(self): super(_DecodePkt, self).__init__("decode_pkt", self.__doc__)
    def invoke(self, arg, from_tty):
        mem = self._mem(arg)
        has_eth, etype = _sniff_start(mem)
        offset = 0
        if has_eth:
            etype, offset = parse_eth(mem, offset)
        _dispatch_l3(mem, offset, etype)


class _DecodeEth(_PktCmd):
    """decode_eth <ptr>  — Ethernet (tagged/untagged) + full L3/L4 chain"""
    def __init__(self): super(_DecodeEth, self).__init__("decode_eth", self.__doc__)
    def invoke(self, arg, from_tty):
        mem = self._mem(arg)
        etype, offset = parse_eth(mem, 0)
        _dispatch_l3(mem, offset, etype)


class _DecodeEthPkt(_PktCmd):
    """decode_eth_pkt <ptr>  — alias for decode_eth"""
    def __init__(self): super(_DecodeEthPkt, self).__init__("decode_eth_pkt", self.__doc__)
    def invoke(self, arg, from_tty):
        mem = self._mem(arg)
        etype, offset = parse_eth(mem, 0)
        _dispatch_l3(mem, offset, etype)


class _DecodeIPv4Pkt(_PktCmd):
    """decode_ipv4_pkt <ptr>  — IPv4 header + L4 chain (no Ethernet)"""
    def __init__(self): super(_DecodeIPv4Pkt, self).__init__("decode_ipv4_pkt", self.__doc__)
    def invoke(self, arg, from_tty):
        mem = self._mem(arg)
        proto, offset = parse_ipv4(mem, 0)
        _dispatch_l4(mem, offset, proto)


class _DecodeIPv6Pkt(_PktCmd):
    """decode_ipv6_pkt <ptr>  — IPv6 header + extension headers + L4 (no Ethernet)"""
    def __init__(self): super(_DecodeIPv6Pkt, self).__init__("decode_ipv6_pkt", self.__doc__)
    def invoke(self, arg, from_tty):
        mem = self._mem(arg)
        nh, offset = parse_ipv6(mem, 0)
        _dispatch_ipv6_chain(mem, offset, nh)


# ─────────────────────────────────────────────────────────────────────────────
# Individual-header commands  (no chain-walking)
# ─────────────────────────────────────────────────────────────────────────────

class _DecodeHdrEth(_PktCmd):
    """decode_hdr_eth <ptr>  — Ethernet + VLAN tags only"""
    def __init__(self): super(_DecodeHdrEth, self).__init__("decode_hdr_eth", self.__doc__)
    def invoke(self, arg, from_tty): parse_eth(self._mem(arg), 0)

class _DecodeHdrIPv4(_PktCmd):
    """decode_hdr_ipv4 <ptr>  — IPv4 header fields only"""
    def __init__(self): super(_DecodeHdrIPv4, self).__init__("decode_hdr_ipv4", self.__doc__)
    def invoke(self, arg, from_tty): parse_ipv4(self._mem(arg), 0)

class _DecodeHdrIPv6(_PktCmd):
    """decode_hdr_ipv6 <ptr>  — IPv6 fixed header fields only"""
    def __init__(self): super(_DecodeHdrIPv6, self).__init__("decode_hdr_ipv6", self.__doc__)
    def invoke(self, arg, from_tty): parse_ipv6(self._mem(arg), 0)

class _DecodeHdrSRH(_PktCmd):
    """decode_hdr_srh <ptr>  — SRH fields + segment list only"""
    def __init__(self): super(_DecodeHdrSRH, self).__init__("decode_hdr_srh", self.__doc__)
    def invoke(self, arg, from_tty): parse_srh(self._mem(arg), 0)

class _DecodeHdrARP(_PktCmd):
    """decode_hdr_arp <ptr>  — ARP header only"""
    def __init__(self): super(_DecodeHdrARP, self).__init__("decode_hdr_arp", self.__doc__)
    def invoke(self, arg, from_tty): parse_arp(self._mem(arg), 0)

class _DecodeHdrICMP(_PktCmd):
    """decode_hdr_icmp <ptr>  — ICMP / ICMPv6 header only"""
    def __init__(self): super(_DecodeHdrICMP, self).__init__("decode_hdr_icmp", self.__doc__)
    def invoke(self, arg, from_tty): parse_icmp(self._mem(arg), 0)

class _DecodeHdrUDP(_PktCmd):
    """decode_hdr_udp <ptr>  — UDP header only"""
    def __init__(self): super(_DecodeHdrUDP, self).__init__("decode_hdr_udp", self.__doc__)
    def invoke(self, arg, from_tty): parse_udp(self._mem(arg), 0)

class _DecodeHdrTCP(_PktCmd):
    """decode_hdr_tcp <ptr>  — TCP header only"""
    def __init__(self): super(_DecodeHdrTCP, self).__init__("decode_hdr_tcp", self.__doc__)
    def invoke(self, arg, from_tty): parse_tcp(self._mem(arg), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Register everything
# ─────────────────────────────────────────────────────────────────────────────

_DecodePkt()
_DecodeEth()
_DecodeEthPkt()
_DecodeIPv4Pkt()
_DecodeIPv6Pkt()
_DecodeHdrEth()
_DecodeHdrIPv4()
_DecodeHdrIPv6()
_DecodeHdrSRH()
_DecodeHdrARP()
_DecodeHdrICMP()
_DecodeHdrUDP()
_DecodeHdrTCP()

print("[pkt_decode] commands registered:")
print("  full chain : decode_pkt  decode_eth  decode_eth_pkt  decode_ipv4_pkt  decode_ipv6_pkt")
print("  single hdr : decode_hdr_{eth,ipv4,ipv6,srh,arp,icmp,udp,tcp}")
