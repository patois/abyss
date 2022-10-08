from abyss import abyss_filter_t
import ida_lines
import ida_diskio
import os
import configparser

CFG_TOKENS = {}
CFG_COLOR_DEFAULT = ida_lines.SCOLOR_ERROR

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
        "token_color1":"SCOLOR_MACRO",
        "token1":"return",
        "token_color2":"SCOLOR_CHAR",
        "token2":"sprintf",
        "token3":"memcpy",
        "token4":"malloc",
        "token5":"free"}
    with open(get_cfg_filename(), "w") as cfg_file:
        config.write(cfg_file)
    return

# ----------------------------------------------------------------------------
def read_cfg():
    global CFG_COLOR
    global CFG_TOKENS

    cfg_file = get_cfg_filename()
    if not os.path.isfile(cfg_file):
        create_cfg_file()
        read_cfg()
        return
    config = configparser.ConfigParser()
    config.read(cfg_file)

    sectname = "init"
    if sectname in config:
        section = config[sectname]
        color = CFG_COLOR_DEFAULT
        for key in section:
            val = section[key]
            if key.startswith("token_color"):
                color = getattr(globals()["ida_lines"], val)
            else:
                if color not in CFG_TOKENS:
                    CFG_TOKENS[color] = []
                CFG_TOKENS[color].append(val)
    return

# ----------------------------------------------------------------------------
class token_colorizer_t(abyss_filter_t):
    """filter that colorizes tokens"""

    def func_printed_ev(self, cfunc):
        pc = cfunc.get_pseudocode()
        for sl in pc:
            for color in CFG_TOKENS:
                for token in CFG_TOKENS[color]:
                    sl.line = sl.line.replace(token, ida_lines.COLSTR(token, color))
        return 0

# ----------------------------------------------------------------------------
def FILTER_INIT():
    read_cfg()
    return token_colorizer_t()