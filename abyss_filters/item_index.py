from abyss import abyss_filter_t
import ida_lines as il
import re

def replace_addr_tags(s):
    tag = "%c%c" % (il.COLOR_ON, il.COLOR_ADDR)
    ti = {}
    p = s.find(tag)
    while p != -1:
        ti[s[p+2:p+2+il.COLOR_ADDR_SIZE]] = 0
        p = s.find(tag, p+2+il.COLOR_ADDR_SIZE)
    for addr in ti.keys():
        s = s.replace(tag+addr, il.COLSTR("<%s>" % addr, il.SCOLOR_AUTOCMT)+tag+addr)
    return s

class color_addr_info_t(abyss_filter_t):
    """This filter assissts in development and debugging of
    Hexrays plugins by prepending item indices"""
    def process_text(self, vu):
        pc = vu.cfunc.get_pseudocode()
        i = 0
        for sl in pc:
            sl.line = replace_addr_tags(sl.line)           
        return

def FILTER_INIT():
    return color_addr_info_t()