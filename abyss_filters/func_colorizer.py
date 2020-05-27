from abyss import abyss_filter_t
import ida_lines

FUNC_NAMES = ["memcpy", "malloc", "free", "realloc", "sprintf"]

class funcname_colorizer_t(abyss_filter_t):
    """example filter which makes function names stand out visually"""

    def __init__(self):
        self.active = True
        return

    def process_text(self, vu):
        pc = vu.cfunc.get_pseudocode()
        for sl in pc:
            for token in FUNC_NAMES:
                sl.line = sl.line.replace(token, ida_lines.COLSTR(token, ida_lines.SCOLOR_ERROR))
        return

def FILTER_INIT():
    return funcname_colorizer_t()