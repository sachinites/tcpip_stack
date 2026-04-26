"""
GDB helper to print atomic_mtrie_node_t details.

Usage:
    (gdb) source script/atomic_mtrie_node.py
    (gdb) atomic_mtrie_node <node_ptr_expr>

Example:
    (gdb) atomic_mtrie_node node
    (gdb) atomic_mtrie_node mtrie->root
"""

import gdb


def _as_u64(val):
    return int(val.cast(gdb.lookup_type("unsigned long long")))


def _node_id_or_zero(ptr_val):
    if _as_u64(ptr_val) == 0:
        return 0
    try:
        return int(ptr_val.dereference()["node_id"])
    except Exception:
        return 0


def _prefix_wildcard_string(node_expr, plen):
    chars = []
    for i in range(plen):
        w = int(gdb.parse_and_eval("bitmap_at(&{}->wildcard, {})".format(node_expr, i)))
        if w:
            chars.append("X")
            continue
        p = int(gdb.parse_and_eval("bitmap_at(&{}->prefix, {})".format(node_expr, i)))
        chars.append("1" if p else "0")
    return "".join(chars)


class AtomicMtrieNodeCmd(gdb.Command):
    def __init__(self):
        super(AtomicMtrieNodeCmd, self).__init__("atomic_mtrie_node", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        arg = arg.strip()
        if not arg:
            raise gdb.GdbError("usage: atomic_mtrie_node <atomic_mtrie_node_t *>")

        node_t = gdb.lookup_type("atomic_mtrie_node_t")
        node_ptr_t = node_t.pointer()

        node_ptr = gdb.parse_and_eval(arg).cast(node_ptr_t)
        node_expr = "((atomic_mtrie_node_t *)({}))".format(arg)

        if _as_u64(node_ptr) == 0:
            gdb.write("null atomic_mtrie_node_t pointer\n")
            return

        node = node_ptr.dereference()

        parent_ptr = node["parent"]
        parent_id = _node_id_or_zero(parent_ptr)

        # Read std::atomic<node*> slots without calling load() (GDB can fail
        # overload resolution and report "Too few arguments in function call").
        zero_child = gdb.parse_and_eval(
            "*((atomic_mtrie_node_t **)&({}->child[0]))".format(node_expr)
        ).cast(node_ptr_t)
        one_child = gdb.parse_and_eval(
            "*((atomic_mtrie_node_t **)&({}->child[1]))".format(node_expr)
        ).cast(node_ptr_t)
        dc_child = gdb.parse_and_eval(
            "*((atomic_mtrie_node_t **)&({}->child[2]))".format(node_expr)
        ).cast(node_ptr_t)

        gdb.write(" ID : %u\n" % int(node["node_id"]))
        plen = int(node["prefix_len"])
        gdb.write(" Prefix/Len : %s/%d\n" % (_prefix_wildcard_string(node_expr, plen), plen))
        gdb.write(" Parent Node = %u\n" % parent_id)
        gdb.write(" ZERO child = %u\n" % _node_id_or_zero(zero_child))
        gdb.write(" ONE child = %u\n" % _node_id_or_zero(one_child))
        gdb.write(" DONT_CARE child = %u\n" % _node_id_or_zero(dc_child))
        gdb.write(" data = %s\n" % str(node["data"]))


AtomicMtrieNodeCmd()
