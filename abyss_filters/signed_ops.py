from abyss import abyss_filter_t
import ida_lines, ida_hexrays as hr
import itertools

SIGNED_EXPR = [
    hr.cot_asgsshr, hr. cot_asgsdiv, hr.cot_asgsmod,
    hr.cot_sge, hr.cot_sle, hr.cot_sgt,
    hr.cot_slt, hr.cot_sshr, hr.cot_sdiv,
    hr.cot_smod]

FMT = "%c%c%" + ("0%dX" % ida_lines.COLOR_ADDR_SIZE)

class signed_op_replacer_t(abyss_filter_t):
    """insert comments into the pseudo-c code.
    comments indicate the use of signed operators."""

    def __init__(self):
        abyss_filter_t.__init__(self)
        self.set_activated(True)
        return

    def tag_signed_ops(self, cf, item_codes):
        ci = hr.ctree_item_t()
        ccode = cf.get_pseudocode()
        for line_idx in range(cf.hdrlines, len(ccode)):
            items = []
            sl = ccode[line_idx]
            for char_idx in range(len(sl.line)):
                if cf.get_line_item(sl.line, char_idx, True, None, ci, None):
                    if ci.it.is_expr() and ci.e.op in item_codes:
                        #print("%s: unsigned op. line %d, pos %d" % (__file__, line_idx+1, char_idx))
                        items.append(ci.it.index)
            for item in list(dict.fromkeys(items)):
                tag = FMT % (ida_lines.COLOR_ON, ida_lines.COLOR_ADDR, item)
                sample = "/*signed*/"
                sl.line = sl.line.replace(tag, tag+ida_lines.COLSTR(sample, ida_lines.SCOLOR_ERROR))

    def process_text(self, vu):
        self.tag_signed_ops(vu.cfunc, SIGNED_EXPR)
        return 0

def FILTER_INIT():
    return signed_op_replacer_t()