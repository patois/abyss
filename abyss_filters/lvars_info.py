from abyss import abyss_filter_t
import ida_lines

class lvars_info_t(abyss_filter_t):
    """renames local variables"""

    def process_printfunc(self, cfunc, printer):
        lvars = cfunc.get_lvars()
        for lvar in lvars:
            if lvar.has_nice_name and not lvar.has_user_name:
                vtype = "s" if lvar.is_stk_var() else "r" if lvar.is_reg_var() else "u"
                suffix = "_%s%d" % (vtype, lvar.width)
                lvar.name += ida_lines.COLSTR(suffix, ida_lines.SCOLOR_AUTOCMT)
                lvar.set_user_name()
        return 0

def FILTER_INIT():
    return lvars_info_t()