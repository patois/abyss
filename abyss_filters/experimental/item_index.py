from abyss import abyss_filter_t
import ida_lines as il
import re

def replace_addr_tags(s):
    tag = "%c%c" % (il.COLOR_ON, il.COLOR_ADDR)
    tag_size = len(tag)
    ti = {}
    p = s.find(tag)
    while p != -1:
        ti[s[p+tag_size:p+tag_size+il.COLOR_ADDR_SIZE]] = 0
        p = s.find(tag, p+tag_size+il.COLOR_ADDR_SIZE)
    for addr in ti.keys():
        s = s.replace(tag+addr, il.COLSTR("<%s>" % addr, il.SCOLOR_AUTOCMT)+tag+addr)
    return s

class color_addr_info_t(abyss_filter_t):
    """This filter makes COLOR_ADDR tags visible in the
    decompiled code (useful only to developers)."""

    def func_printed_ev(self, cfunc):
        pc = cfunc.get_pseudocode()
        for sl in pc:
            sl.line = replace_addr_tags(sl.line)           
        return 0

def FILTER_INIT():
    return color_addr_info_t()