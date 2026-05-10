"""
GDB helpers to traverse and print mtrie_t (libs/mtrie/mtrie.h), including optional
dump of rtm_route* payloads when mtrie holds RTM LPM routes (node->data).

Usage:
    (gdb) source scripts/mtrie_dump.py
    (gdb) mtrie_dump <mtrie_t *expr>
    (gdb) mtrie_dump <mtrie_t *expr> routes
    (gdb) sanity_check <mtrie_t *expr> [abort]

Examples:
    (gdb) mtrie_dump rtm->lpm_rt_tree
    (gdb) mtrie_dump rtm->lpm_rt_tree routes
    (gdb) sanity_check rtm->lpm_rt_tree

sanity_check validates parent/child linkage, bitmap tsize/next fields, unused
tail bits, branch slot vs bitmap_effective_bit_at (libs/BitOp/bitmap.c), leaf
data (matches mtrie_longest_prefix_match_search in libs/mtrie/mtrie.c), and
DFS node count vs mtrie->N. On failure it raises gdb.GdbError with an ASSERT
message; optional \"abort\" calls the inferior's abort() after printing.

The "routes" variant lists only nodes with non-NULL data and prints
rtm_route.prefix (IPv4/IPv6 string) plus ridx and mtrie_node_id.

Bitmap bits are read via inferior memory (libs/BitOp/bitmap.c bitmap_at logic)
instead of calling bitmap_at() in the inferior — GDB often forbids inferior calls
when stopped in another thread or with certain scheduler-lock settings.
"""

import gdb
import socket
import struct

AF_IPV4 = 0
AF_IPV6 = 1

CHILD_NAMES = ("ZERO", "ONE", "DONT_CARE")

BIT_ZERO = 0
BIT_ONE = 1
BIT_DONT_CARE = 2
BIT_TYPE_MAX = 3


def _as_u64(val):
    return int(val.cast(gdb.lookup_type("unsigned long long")))


def _node_id_or_zero(ptr_val):
    if _as_u64(ptr_val) == 0:
        return 0
    try:
        return int(ptr_val.dereference()["node_id"])
    except Exception:
        return 0


def _fail(msg, node_id=None, abort_inferior=False):
    extra = " [node_id=%s]" % node_id if node_id is not None else ""
    line = "mtrie sanity_check ASSERT:%s %s\n" % (extra, msg)
    gdb.write(line)
    if abort_inferior:
        try:
            gdb.execute("call abort()", to_string=True)
        except gdb.error:
            pass
    raise gdb.GdbError("mtrie sanity_check failed: %s" % msg)


def _inferior_read_u32(addr):
    """Read uint32 from inferior at addr using the inferior's endianness."""
    addr = int(addr)
    if addr == 0:
        return 0
    inf = gdb.selected_inferior()
    try:
        raw = inf.read_memory(addr, 4)
    except gdb.MemoryError as exc:
        raise gdb.GdbError("read_memory failed at %#x: %s" % (addr, exc))
    arch = inf.architecture()
    le = getattr(gdb, "ENDIAN_LITTLE", 0)
    be = getattr(gdb, "ENDIAN_BIG", 1)
    try:
        end = arch.endian()
        if end == le:
            return struct.unpack("<I", raw)[0] & 0xFFFFFFFF
        if end == be:
            return struct.unpack(">I", raw)[0] & 0xFFFFFFFF
    except (AttributeError, gdb.error, Exception):
        pass
    return struct.unpack("<I", raw)[0] & 0xFFFFFFFF


def _bitmap_at_val(bmp_val, index):
    """
    Same bit semantics as libs/BitOp/bitmap.c bitmap_at(), without calling the inferior:
      word = * (uint32_t *)(bits + (index/32)*4);
      return (htonl(word) & (1 << (32 - (index%32) - 1))) != 0
    """
    tsize = int(bmp_val["tsize"])
    if index >= tsize:
        return False
    bits_addr = int(bmp_val["bits"])
    if bits_addr == 0:
        return False
    n_blocks = index // 32
    bit_pos = index % 32
    word = _inferior_read_u32(bits_addr + n_blocks * 4)
    nw = socket.htonl(word)
    return (nw & (1 << (32 - bit_pos - 1))) != 0


def _effective_bit_at_val(prefix_val, wildcard_val, pos):
    """bitmap_effective_bit_at(prefix, wildcard, pos) without inferior calls."""
    if _bitmap_at_val(wildcard_val, pos):
        return BIT_DONT_CARE
    if _bitmap_at_val(prefix_val, pos):
        return BIT_ONE
    return BIT_ZERO


def _tail_bits_zero_val(bmp_val, start, tsize):
    for i in range(start, tsize):
        if _bitmap_at_val(bmp_val, i):
            return False, i
    return True, None


def _fmt_node(addr, node_id):
    return "mtrie_node_t*=%#x node_id=%s" % (addr, node_id)


def _prefix_wildcard_string_from_node(node_val, plen):
    """Match mtrie_print_node / bitmap_prefix_print bit display for indices [0, plen)."""
    pfx = node_val["prefix"]
    wld = node_val["wildcard"]
    chars = []
    for i in range(plen):
        if _bitmap_at_val(wld, i):
            chars.append("X")
        elif _bitmap_at_val(pfx, i):
            chars.append("1")
        else:
            chars.append("0")
    return "".join(chars)


def _format_cmn_prefix(pfx_val):
    """Format cmn_prefix_t (libs/common/cmn_prefix.h) for AF_IPV4 / AF_IPV6."""
    try:
        afi = int(pfx_val["afi"])
        plen = int(pfx_val["prefix_len"])
        u = pfx_val["u"]
    except Exception as exc:
        return "<cmn_prefix: %s>" % exc

    if afi == AF_IPV4:
        addr = int(u["v4_addr"]) & 0xFFFFFFFF
        ip = socket.inet_ntoa(struct.pack("I", addr))
        return "%s/%d" % (ip, plen)

    if afi == AF_IPV6:
        parts = [int(u["v6_addr"][i]) for i in range(8)]
        raw = struct.pack(">8H", *parts)
        ip = socket.inet_ntop(socket.AF_INET6, raw)
        return "%s/%d" % (ip, plen)

    return "afi=%d len=%d" % (afi, plen)


class MtrieSanityCheckCmd(gdb.Command):
    """Deep consistency checks for mtrie_t / mtrie_node_t (see libs/mtrie/mtrie.c, libs/BitOp/bitmap.c)."""

    def __init__(self):
        super(MtrieSanityCheckCmd, self).__init__(
            "sanity_check", gdb.COMMAND_DATA, gdb.COMPLETE_EXPRESSION
        )

    def invoke(self, arg, from_tty):
        arg = (arg or "").strip()
        if not arg:
            raise gdb.GdbError("usage: sanity_check <mtrie_t *> [abort]")

        parts = arg.split()
        abort_inf = len(parts) >= 2 and parts[-1].lower() == "abort"
        if abort_inf:
            mtrie_expr = " ".join(parts[:-1])
        else:
            mtrie_expr = arg

        if not mtrie_expr:
            raise gdb.GdbError("usage: sanity_check <mtrie_t *> [abort]")

        mtrie_ptr = gdb.parse_and_eval(mtrie_expr).cast(gdb.lookup_type("mtrie_t").pointer())
        if _as_u64(mtrie_ptr) == 0:
            _fail("mtrie_t* is NULL", abort_inferior=abort_inf)

        mtrie = mtrie_ptr.dereference()
        node_ptr_t = gdb.lookup_type("mtrie_node_t").pointer()
        root = mtrie["root"].cast(node_ptr_t)
        max_plen = int(mtrie["prefix_len"])
        n_book = int(mtrie["N"])

        if _as_u64(root) == 0:
            _fail("mtrie->root is NULL", abort_inferior=abort_inf)

        if max_plen <= 0 or (max_plen % 32) != 0:
            _fail("mtrie->prefix_len must be positive and multiple of 32 (bitmap_init), got %d" % max_plen)

        st = mtrie["stack"]
        if _as_u64(st) == 0:
            _fail("mtrie->stack is NULL (init_mtrie always allocates a stack)", abort_inferior=abort_inf)

        visited = set()
        seen_ids = {}
        dfs_count = 0
        leaf_count = 0

        def visit(node_ptr, parent_ptr, parent_slot, is_root):
            nonlocal dfs_count, leaf_count

            addr = _as_u64(node_ptr)
            if addr == 0:
                _fail("unexpected NULL mtrie_node_t* in tree walk", abort_inferior=abort_inf)

            if addr in visited:
                nid = None
                try:
                    nid = int(node_ptr.dereference()["node_id"])
                except Exception:
                    pass
                _fail(
                    "cycle / shared mtrie_node_t: %s" % _fmt_node(addr, nid),
                    node_id=nid,
                    abort_inferior=abort_inf,
                )
            visited.add(addr)
            dfs_count += 1

            node = node_ptr.dereference()
            nid = int(node["node_id"])
            if nid in seen_ids and seen_ids[nid] != addr:
                _fail(
                    "duplicate node_id %u (nodes %#x and %#x)"
                    % (nid, seen_ids[nid], addr),
                    node_id=nid,
                    abort_inferior=abort_inf,
                )
            seen_ids[nid] = addr

            plen = int(node["prefix_len"])
            if plen < 0 or plen > max_plen:
                _fail(
                    "prefix_len %d out of range [0,%d] at %s"
                    % (plen, max_plen, _fmt_node(addr, nid)),
                    node_id=nid,
                    abort_inferior=abort_inf,
                )

            if is_root:
                if _as_u64(node["parent"]) != 0:
                    _fail(
                        "root node must have parent==NULL (%s)" % _fmt_node(addr, nid),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )
                if plen != 0:
                    _fail(
                        "root node must have prefix_len==0 (%s)" % _fmt_node(addr, nid),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )
            else:
                if _as_u64(node["parent"]) == 0:
                    _fail(
                        "non-root node has parent==NULL (%s)" % _fmt_node(addr, nid),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )
                if _as_u64(node["parent"]) != _as_u64(parent_ptr):
                    _fail(
                        "node->parent does not match traversal parent (%s)" % _fmt_node(addr, nid),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )
                if parent_slot is None:
                    _fail("internal error: non-root missing parent_slot", abort_inferior=abort_inf)
                eff = _effective_bit_at_val(node["prefix"], node["wildcard"], 0)
                if eff != parent_slot:
                    _fail(
                        "child branch slot %s does not match bitmap_effective_bit_at(prefix,wildcard,0)=%d at %s"
                        % (CHILD_NAMES[parent_slot], eff, _fmt_node(addr, nid)),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )
                if plen == 0:
                    _fail(
                        "non-root node has prefix_len==0 (%s)" % _fmt_node(addr, nid),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )

            for bm_name in ("prefix", "wildcard", "stacked_prefix"):
                bmp = node[bm_name]
                tsize = int(bmp["tsize"])
                if tsize != max_plen:
                    _fail(
                        "node %s.tsize=%u != mtrie->prefix_len=%u at %s"
                        % (bm_name, tsize, max_plen, _fmt_node(addr, nid)),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )
                bits = bmp["bits"]
                if tsize > 0 and _as_u64(bits) == 0:
                    _fail(
                        "node %s.bits is NULL with tsize>0 at %s" % (bm_name, _fmt_node(addr, nid)),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )

            p_next = int(node["prefix"]["next"])
            w_next = int(node["wildcard"]["next"])
            if p_next != plen:
                _fail(
                    "prefix.next=%u != prefix_len=%u (%s); bitmap_fast_copy/bitmap_copy_at_offset extent"
                    % (p_next, plen, _fmt_node(addr, nid)),
                    node_id=nid,
                    abort_inferior=abort_inf,
                )
            if w_next != plen:
                _fail(
                    "wildcard.next=%u != prefix_len=%u (%s)"
                    % (w_next, plen, _fmt_node(addr, nid)),
                    node_id=nid,
                    abort_inferior=abort_inf,
                )

            for bm_name in ("prefix", "wildcard"):
                ok, bad_idx = _tail_bits_zero_val(node[bm_name], plen, max_plen)
                if not ok:
                    _fail(
                        "non-zero %s bit at index %u past prefix_len=%u (%s)"
                        % (bm_name, bad_idx, plen, _fmt_node(addr, nid)),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )

            ch_addrs = []
            for slot in range(BIT_TYPE_MAX):
                ch = node["child"][slot].cast(node_ptr_t)
                ca = _as_u64(ch)
                ch_addrs.append(ca)
                if ca != 0:
                    if ca == addr:
                        _fail(
                            "node is its own child[%s] (%s)"
                            % (CHILD_NAMES[slot], _fmt_node(addr, nid)),
                            node_id=nid,
                            abort_inferior=abort_inf,
                        )
                    pch = ch.dereference()["parent"]
                    if _as_u64(pch) != addr:
                        _fail(
                            "child[%s]->parent does not point back to parent (%s)"
                            % (CHILD_NAMES[slot], _fmt_node(addr, nid)),
                            node_id=nid,
                            abort_inferior=abort_inf,
                        )

            for i in range(BIT_TYPE_MAX):
                for j in range(i + 1, BIT_TYPE_MAX):
                    if ch_addrs[i] and ch_addrs[i] == ch_addrs[j]:
                        _fail(
                            "duplicate non-NULL child pointers in slots %s and %s (%s)"
                            % (CHILD_NAMES[i], CHILD_NAMES[j], _fmt_node(addr, nid)),
                            node_id=nid,
                            abort_inferior=abort_inf,
                        )

            is_leaf = (
                ch_addrs[BIT_ZERO] == 0
                and ch_addrs[BIT_ONE] == 0
                and ch_addrs[BIT_DONT_CARE] == 0
            )
            if is_leaf:
                leaf_count += 1
                # mtrie_longest_prefix_match_search asserts data only on leaves reached by lookup;
                # the trie root with no children is a leaf with data==NULL (init_mtrie).
                if (not is_root) and _as_u64(node["data"]) == 0:
                    _fail(
                        "non-root leaf has NULL data (see mtrie_longest_prefix_match_search) (%s)"
                        % _fmt_node(addr, nid),
                        node_id=nid,
                        abort_inferior=abort_inf,
                    )

            for slot in range(BIT_TYPE_MAX):
                ch = node["child"][slot].cast(node_ptr_t)
                if _as_u64(ch) != 0:
                    visit(ch, node_ptr, slot, False)

        visit(root, None, None, True)

        if dfs_count != n_book:
            _fail(
                "DFS node count %u != mtrie->N=%u (missing/extra nodes or bad links)"
                % (dfs_count, n_book),
                abort_inferior=abort_inf,
            )

        gdb.write(
            "sanity_check OK: mtrie@%s  N=%u  nodes_visited=%u  leaves=%u  prefix_len=%u\n"
            % (mtrie_expr, n_book, dfs_count, leaf_count, max_plen)
        )


MtrieSanityCheckCmd()


class MtrieDumpCmd(gdb.Command):
    def __init__(self):
        super(MtrieDumpCmd, self).__init__("mtrie_dump", gdb.COMMAND_DATA, gdb.COMPLETE_EXPRESSION)

    def invoke(self, arg, from_tty):
        arg = (arg or "").strip()
        if not arg:
            raise gdb.GdbError("usage: mtrie_dump <mtrie_t *> [routes]")

        parts = arg.split()
        if len(parts) >= 2 and parts[-1].lower() == "routes":
            routes_only = True
            mtrie_expr = " ".join(parts[:-1])
        else:
            routes_only = False
            mtrie_expr = arg

        mtrie_t = gdb.lookup_type("mtrie_t")
        mtrie_ptr_t = mtrie_t.pointer()
        node_ptr_t = gdb.lookup_type("mtrie_node_t").pointer()

        mtrie_ptr = gdb.parse_and_eval(mtrie_expr).cast(mtrie_ptr_t)
        if _as_u64(mtrie_ptr) == 0:
            gdb.write("null mtrie_t*\n")
            return

        mtrie = mtrie_ptr.dereference()
        root = mtrie["root"].cast(node_ptr_t)
        max_prefix_bits = int(mtrie["prefix_len"])
        n_nodes = int(mtrie["N"])

        gdb.write(
            "mtrie@%s  N=%u  prefix_len=%u  root=%s\n"
            % (mtrie_expr, n_nodes, max_prefix_bits, str(mtrie["root"]))
        )

        visited = set()

        def walk(node_ptr, depth):
            addr = _as_u64(node_ptr)
            if addr == 0:
                return
            if addr in visited:
                gdb.write("%scycle: mtrie_node_t %s\n" % ("  " * depth, hex(addr)))
                return
            visited.add(addr)

            node = node_ptr.dereference()
            plen = int(node["prefix_len"])
            if plen < 0:
                plen = 0
            eff_plen = min(plen, max_prefix_bits) if max_prefix_bits else plen

            pw = _prefix_wildcard_string_from_node(node, eff_plen) if eff_plen else ""

            data_ptr = node["data"]
            has_data = _as_u64(data_ptr) != 0

            if routes_only:
                if has_data:
                    try:
                        route_ptr = data_ptr.cast(gdb.lookup_type("rtm_route").pointer())
                        route = route_ptr.dereference()
                        pfx_s = _format_cmn_prefix(route["prefix"])
                        gdb.write(
                            "  route %s  ridx=%u  mtrie_node_id=%u  node=%s  data=%s\n"
                            % (
                                pfx_s,
                                int(route["ridx"]),
                                int(node["node_id"]),
                                hex(addr),
                                str(data_ptr),
                            )
                        )
                    except Exception as exc:
                        gdb.write(
                            "  (route @ %s decode failed: %s)  node_id=%u\n"
                            % (str(data_ptr), exc, int(node["node_id"]))
                        )
            else:
                indent = "  " * depth
                gdb.write("%snode_id=%u  parent=%u  %s/%u\n" % (indent, int(node["node_id"]), _node_id_or_zero(node["parent"]), pw, eff_plen))
                gdb.write(
                    "%s  children: %s=%u %s=%u %s=%u  data=%s\n"
                    % (
                        indent,
                        CHILD_NAMES[0],
                        _node_id_or_zero(node["child"][0]),
                        CHILD_NAMES[1],
                        _node_id_or_zero(node["child"][1]),
                        CHILD_NAMES[2],
                        _node_id_or_zero(node["child"][2]),
                        str(data_ptr),
                    )
                )
                if has_data:
                    try:
                        route_ptr = data_ptr.cast(gdb.lookup_type("rtm_route").pointer())
                        route = route_ptr.dereference()
                        pfx_s = _format_cmn_prefix(route["prefix"])
                        gdb.write("%s  rtm_route: %s  ridx=%u\n" % (indent, pfx_s, int(route["ridx"])))
                    except Exception as exc:
                        gdb.write("%s  (rtm_route decode failed: %s)\n" % (indent, exc))

            for i in range(3):
                walk(node["child"][i].cast(node_ptr_t), depth + 1)

        walk(root, 0)


MtrieDumpCmd()
