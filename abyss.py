import ida_kernwin as kw
import ida_hexrays as hr
import ida_diskio, ida_idaapi
import os, sys

__author__ = "https://github.com/patois"

PLUGIN_NAME = "abyss"
ACTION_NAME = PLUGIN_NAME+":"
POPUP_ENTRY = PLUGIN_NAME+"/"
FILTER_DIR = PLUGIN_NAME+"_filters"
FILTERS = {}

# ----------------------------------------------------------------------------
class abyss_filter_t:
    def __init__(self):
        self.active = False
        return

    def process_text(self, vu):
        pass

    def process_curpos(self, vu):
        pass

    def _is_active(self):
        return self.active

    def _set_active(self, active):
        self.active = active

# ----------------------------------------------------------------------------
def load_filters(reload=False):
    global FILTERS

    print("%s: %sloading filters..." % (PLUGIN_NAME, "re" if reload else ""))
    if reload:
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
    return

# ----------------------------------------------------------------------------
class ui_event_t(kw.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup_handle):
            if kw.get_widget_type(widget) == kw.BWN_PSEUDOCODE:
                class FilterHandler(kw.action_handler_t):
                    def __init__(self, name):
                        self.name = name
                        kw.action_handler_t.__init__(self)

                    def activate(self, ctx):
                        obj = FILTERS[self.name]
                        obj._set_active(not obj._is_active())
                        vu = hr.get_widget_vdui(ctx.widget)
                        if vu:
                            vu.refresh_view(False)
                        return 1

                    def update(self, ctx):
                        return kw.AST_ENABLE_FOR_WIDGET

                for name, obj in FILTERS.items():
                    action_desc = kw.action_desc_t(
                        '%s%s' % (ACTION_NAME, name),
                        name,
                        FilterHandler(name),
                        None,
                        None,
                        34 if obj._is_active() else -1)
                    kw.attach_dynamic_action_to_popup(widget, popup_handle, action_desc, POPUP_ENTRY)

# ----------------------------------------------------------------------------
class hx_event_t(hr.Hexrays_Hooks):
    def __init__(self):
        hr.Hexrays_Hooks.__init__(self)

    def text_ready(self, vu):
        for name, obj in FILTERS.items():
            if obj._is_active():
                obj.process_text(vu)
        return 0

    def curpos(self, vu):
        for name, obj in FILTERS.items():
            if obj._is_active():
                obj.process_curpos(vu)
        return 0
        
# ----------------------------------------------------------------------------
class abyss_plugin_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "Postprocess Hexrays Output"
    help = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-R"

    def init(self):
        if hr.init_hexrays_plugin():
            load_filters()
            self.ui_hooks = ui_event_t()
            self.ui_hooks.hook()
            self.hr_hooks = hx_event_t()
            self.hr_hooks.hook()
            return ida_idaapi.PLUGIN_KEEP
        else:
            return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        load_filters(reload=True)

    def term(self):
        self.ui_hooks.unhook()
        self.hr_hooks.unhook()

def PLUGIN_ENTRY():
    return abyss_plugin_t()