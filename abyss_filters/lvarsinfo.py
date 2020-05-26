from abyss import abyss_filter_t
import ida_lines
import re

class LvarsInfo(abyss_filter_t):
    """renames local variables non-destructively.
    this code is buggy, fixme"""

    def process_text(self, vu):
        vars_dict = {}
        lvars = vu.cfunc.get_lvars()
        for lvar in lvars:
            if len(lvar.name):
                vtype = "s" if lvar.is_stk_var() else "r" if lvar.is_reg_var() else "u"
                suffix = "_%s%d" % (vtype, lvar.width)
                print("%s -> %s" % (lvar.name, lvar.name+suffix))
                vars_dict[lvar.name] = "%s%s" % (lvar.name, ida_lines.COLSTR(suffix, ida_lines.SCOLOR_AUTOCMT))

        pc = vu.cfunc.get_pseudocode()
        for sl in pc:
            for name, newname in vars_dict.items():
                sl.line = re.sub(r"\b%s\b" % name, newname, sl.line)
        return

def FILTER_INIT():
    return LvarsInfo()