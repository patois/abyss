from abyss import abyss_filter_t
import ida_lines
import ida_diskio
import ida_hexrays as hr
import os
import configparser

FMT = "%c%c%" + ("0%dX" % ida_lines.COLOR_ADDR_SIZE)
CFG_DEFAULT_COLOR = "SCOLOR_REGCMT"
CFG_COMMENT = "/*signed*/"
CFG_COLOR = None

SIGNED_OPS = [hr.cot_asgsshr,
            hr. cot_asgsdiv,
            hr.cot_asgsmod,
            hr.cot_sge,
            hr.cot_sle,
            hr.cot_sgt,
            hr.cot_slt,
            hr.cot_sshr,
            hr.cot_sdiv,
            hr.cot_smod]

# ----------------------------------------------------------------------------
def get_self_filename():
    mod, _ = os.path.splitext(os.path.basename(__file__))
    return mod

# ----------------------------------------------------------------------------
def get_cfg_filename():
    """returns full path of config file name."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "cfg",
        "abyss_%s.cfg" % get_self_filename())

# ----------------------------------------------------------------------------
def create_cfg_file():
    config = configparser.ConfigParser()
    config["init"] = {
        "comment":"%s" % CFG_COMMENT,
        "color":"%s" % CFG_DEFAULT_COLOR}
    with open(get_cfg_filename(), "w") as cfg_file:
        config.write(cfg_file)
    return

# ----------------------------------------------------------------------------
def read_cfg():
    global CFG_COLOR
    global CFG_COMMENT

    cfg_file = get_cfg_filename()
    if not os.path.isfile(cfg_file):
        create_cfg_file()
        read_cfg()
        return
    config = configparser.ConfigParser()
    config.read(cfg_file)

    CFG_COLOR = getattr(
                    globals()["ida_lines"],
                    config.get("init", "color", fallback=CFG_DEFAULT_COLOR))
    CFG_COMMENT = config.get("init", "comment", fallback=CFG_COMMENT)
    return

# ----------------------------------------------------------------------------
class signed_op_replacer_t(abyss_filter_t):
    """insert additional comments into the pseudo-c code.
    comments indicate the use of signed operations."""

    def tag_signed_ops(self, cf, item_codes):
        ci = hr.ctree_item_t()
        ccode = cf.get_pseudocode()
        for line_idx in range(cf.hdrlines, len(ccode)):
            items = []
            sl = ccode[line_idx]
            for char_idx in range(len(sl.line)):
                if cf.get_line_item(sl.line, char_idx, True, None, ci, None):
                    if ci.it.is_expr() and ci.e.op in item_codes:
                        #print("%s: signed op. line %d, pos %d" % (__file__, line_idx+1, char_idx))
                        items.append(ci.it.index)
            for item in list(dict.fromkeys(items)):
                tag = FMT % (ida_lines.COLOR_ON, ida_lines.COLOR_ADDR, item)
                sl.line = sl.line.replace(tag, tag+ida_lines.COLSTR(CFG_COMMENT, CFG_COLOR))

    def func_printed_ev(self, cfunc):
        self.tag_signed_ops(cfunc, SIGNED_OPS)
        return 0

# ----------------------------------------------------------------------------
def FILTER_INIT():
    read_cfg()
    return signed_op_replacer_t()