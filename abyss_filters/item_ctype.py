from abyss import abyss_filter_t
import ida_lines as il
import ida_hexrays
import re

def replace_addr_tags(cfunc, s):
    tag = "%c%c" % (il.COLOR_ON, il.COLOR_ADDR)
    tag_size = len(tag)
    ti = {}
    p = s.find(tag)
    while p != -1:
        ti[s[p+tag_size:p+tag_size+il.COLOR_ADDR_SIZE]] = 0
        p = s.find(tag, p+tag_size+il.COLOR_ADDR_SIZE)
    for addr in ti.keys():
        idx = int(addr, 16)
        a = ida_hexrays.ctree_anchor_t()
        a.value = idx
        if a.is_valid_anchor() and a.is_citem_anchor():
            item = cfunc.treeitems.at(a.get_index())
            if item:
                ctype_name = ida_hexrays.get_ctype_name(item.op)
                s = s.replace(tag+addr, il.COLSTR("<%s>" % ctype_name, il.SCOLOR_AUTOCMT)+tag+addr)
    return s

class item_ctype_info_t(abyss_filter_t):
    """This filter prepends ctype names (useful only to developers)."""

    def process_text(self, cfunc):
        pc = cfunc.get_pseudocode()
        for sl in pc:
            sl.line = replace_addr_tags(cfunc, sl.line)           
        return 0

def FILTER_INIT():
    return item_ctype_info_t()