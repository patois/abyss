import ida_kernwin as kw
import ida_hexrays as hr
import ida_diskio, ida_idaapi
import os, sys, configparser

__author__ = "https://github.com/patois"

DEBUG = False

PLUGIN_NAME = "abyss"
ACTION_NAME = "%s:" % PLUGIN_NAME
POPUP_ENTRY = "%s/" % PLUGIN_NAME
FILTER_DIR = "%s_filters" % PLUGIN_NAME
CFG_FILENAME = "%s.cfg" % PLUGIN_NAME

FILTERS = {}

# ----------------------------------------------------------------------------
def dbg_print(s):
    if DEBUG:
        print("%s" % s)

# ----------------------------------------------------------------------------
class abyss_filter_t:
    """new filters should inherit from this class and
    override respective handlers/methods"""
 
    def __init__(self):
        self.set_activated(False)
        return

    def finish_populating_widget_popup_ev(self, widget, popup_handle):
        return

    def refresh_pseudocode_ev(self, vu):
        return 0

    def print_func_ev(self, cfunc, printer):
        return 0

    def func_printed_ev(self, cfunc):
        return 0

    def curpos_ev(self, vu):
        return 0

    def maturity_ev(self, cfunc, new_maturity):
        return 0

    def create_hint_ev(self, vu):
        return 0

    def get_lines_rendering_info_ev(self, out, widget, info):
        return

    def screen_ea_changed_ev(self, ea, prev_ea):
        return

    def is_activated(self):
        return self.activated

    def set_activated(self, active):
        self.activated = active

# ----------------------------------------------------------------------------
def get_cfg_filename():
    """returns full path of abyss config file."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "cfg",
        "%s" % CFG_FILENAME)

# ----------------------------------------------------------------------------
def apply_cfg(reload=False, filters={}):
    """loads abyss configuration."""

    cfg_file = get_cfg_filename()
    kw.msg("%s: %sloading %s...\n" % (PLUGIN_NAME,
        "re" if reload else "",
        cfg_file))
    if not os.path.isfile(cfg_file):
        kw.msg("%s: default configuration (%s) does not exist!\n" % (PLUGIN_NAME, cfg_file))
        kw.msg("Creating default configuration\n")
        try:
            with open(cfg_file, "w") as f:
                f.write("[init]\n")
                for name, mod in filters.items():
                    f.write("%s=False\n" % name )
        except:
            kw.msg("failed!\n")
            return False
        return apply_cfg(reload=True)

    config = configparser.ConfigParser()
    config.read(cfg_file)

    # read all sections
    for section in config.sections():
        if section == "init":
            for name, value in config.items(section):
                try:
                    filters[name].set_activated(config[section].getboolean(name))
                    dbg_print("%s -> %s" % (name, value))
                except:
                    pass
    kw.msg("done!\n")
    return True

# ----------------------------------------------------------------------------
def load_filters(reload=False):
    global FILTERS

    print("%s: %sloading filters..." % (PLUGIN_NAME, "re" if reload else ""))
    if reload:
        # TODO: properly clean-up and unload filters
        #       implement FILTER_EXIT
        FILTERS = {}
    filterdir = os.path.join(os.path.dirname(__file__), FILTER_DIR)
    if os.path.exists(filterdir):
        for entry in os.listdir(filterdir):
            if entry.lower().endswith(".py") and entry.lower() != "__init__.py":
                mod, ext = os.path.splitext(entry)
                if mod not in FILTERS:
                    try:
                        ida_idaapi.require("%s.%s" % (FILTER_DIR, mod), FILTER_DIR)
                        flt = sys.modules["%s.%s" % (FILTER_DIR, mod)].FILTER_INIT()
                        if flt:
                            print("  loaded: \"%s\"" % (mod))
                            FILTERS[mod] = flt
                    except ModuleNotFoundError:
                        print("  failed: \"%s\"" % (mod))
        apply_cfg(reload, FILTERS)
    return

# ----------------------------------------------------------------------------
class ui_event_t(kw.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        if kw.get_widget_type(widget) == kw.BWN_PSEUDOCODE:
            class FilterHandler(kw.action_handler_t):
                def __init__(self, name):
                    self.name = name
                    kw.action_handler_t.__init__(self)

                # on-click event handler for pop-up menu
                def activate(self, ctx):
                    # toggle activated state for current filter
                    obj = FILTERS[self.name]
                    obj.set_activated(not obj.is_activated())
                    # refresh current decompiler widget
                    vu = hr.get_widget_vdui(ctx.widget)
                    if vu:
                        vu.refresh_view(not obj.is_activated())
                    return 1

                def update(self, ctx):
                    return kw.AST_ENABLE_FOR_WIDGET

            # dynamically create event handler for each filter
            # and attach to pop-up menu
            for name, obj in FILTERS.items():
                action_desc = kw.action_desc_t(
                    '%s%s' % (ACTION_NAME, name),
                    name,
                    FilterHandler(name),
                    None,
                    None,
                    34 if obj.is_activated() else -1)
                kw.attach_dynamic_action_to_popup(widget, popup_handle, action_desc, POPUP_ENTRY)

            # forward event finish_populating_widget_popup to activated filters
            for name, obj in FILTERS.items():
                if obj.is_activated():
                    obj.finish_populating_widget_popup_ev(widget, popup_handle)
            return
    
    # forward event screen_ea_changed to activated filters
    def screen_ea_changed(self, ea, prev_ea):
        for name, obj in FILTERS.items():
            if obj.is_activated():
                obj.screen_ea_changed_ev(ea, prev_ea)
        return

    # forward event get_lines_rendering_info to activated filters
    def get_lines_rendering_info(self, out, widget, info):
        if kw.get_widget_type(widget) == kw.BWN_PSEUDOCODE:
            for name, obj in FILTERS.items():
                if obj.is_activated():
                    obj.get_lines_rendering_info_ev(out, widget, info)
        return

# ----------------------------------------------------------------------------
"""
via hexrays.hpp:
/// When the possible return value is not specified, your callback
/// must return zero.
"""
class hx_event_t(hr.Hexrays_Hooks):
    def __init__(self):
        hr.Hexrays_Hooks.__init__(self)

    # forward event refresh_pseudocode to activated filters
    def refresh_pseudocode(self, vu):
        for name, obj in FILTERS.items():
            if obj.is_activated():
                # TBD
                obj.refresh_pseudocode_ev(vu)
        return 0

    # forward event print_func to activated filters
    def print_func(self, cfunc, vp):
        """via hexrays.hpp:
        ///< Returns: 1 if text has been generated by the plugin
        ///< It is forbidden to modify ctree at this event.
        """
        custom_text = 0
        for name, obj in FILTERS.items():
            if obj.is_activated():
                custom_text |= obj.print_func_ev(cfunc, vp)
        return custom_text != 0

    # forward event func_printed to activated filters
    def func_printed(self, cfunc):
        ret = 0
        for name, obj in FILTERS.items():
            if obj.is_activated():
                # TBD
                ret |= obj.func_printed_ev(cfunc)
        return 0

    # forward event curpos to activated filters
    def curpos(self, vu):
        ret = 0
        for name, obj in FILTERS.items():
            if obj.is_activated():
                # TBD
                ret |= obj.curpos_ev(vu)
        return 0

    # forward event maturity to activated filters
    def maturity(self, cfunc, new_maturity):
        ret = 0
        for name, obj in FILTERS.items():
            if obj.is_activated():
                # TBD
                ret |= obj.maturity_ev(cfunc, new_maturity)
        return 0

    # forward event create_hint to activated filters
    def create_hint(self, vu):
        lines = ""
        count = 0
        for name, obj in FILTERS.items():
            if obj.is_activated():
                # TBD
                ret = obj.create_hint_ev(vu)
                if ret and isinstance(ret, tuple) and len(ret) == 3:
                    rv, l, n = ret
                    lines += l
                    count += n
        if not count:
            return 0
        return (2, lines, count)

# ----------------------------------------------------------------------------
class abyss_plugin_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "Postprocess Hexrays Output"
    help = comment
    wanted_name = PLUGIN_NAME
    # pressing this hotkey will reload any filter scripts
    # without having to restart IDA (useful during development)
    wanted_hotkey = "Ctrl-Alt-R"

    def init(self):
        if hr.init_hexrays_plugin():
            load_filters()
            self.ui_hooks = ui_event_t()
            self.ui_hooks.hook()
            self.hr_hooks = hx_event_t()
            self.hr_hooks.hook()
            return ida_idaapi.PLUGIN_KEEP
        return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        load_filters(reload=True)
        return

    def term(self):
        try:
            self.ui_hooks.unhook()
            self.hr_hooks.unhook()
        except:
            pass
        return

# ----------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return abyss_plugin_t()