from abyss import abyss_filter_t
import ida_lines, ida_pro

FUNC_NAMES = [
    "memcpy", "memmove", "strcpy", "gets", "malloc", "free",
    "realloc", "sprintf", "system", "popen"]

class funcname_colorizer_t(abyss_filter_t):
    """example filter which makes function names stand out visually"""

    def process_text(self, cfunc):
        pc = cfunc.get_pseudocode()
        for sl in pc:
            for token in FUNC_NAMES:
                sl.line = sl.line.replace(token, ida_lines.COLSTR(token, ida_lines.SCOLOR_ERROR))
        return 0

def FILTER_INIT():
    return funcname_colorizer_t()