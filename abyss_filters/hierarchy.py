from abyss import abyss_filter_t
from ida_idaapi import BADADDR
import ida_kernwin, ida_hexrays, ida_funcs, idautils, ida_name, ida_bytes, ida_ua, ida_idp

MAX_DEPTH = 4
MAX_FUNC = 30

def Callees(ea):
    pfn = ida_funcs.get_func(ea)
    callees = []
    if pfn:
        for item in pfn:
            F = ida_bytes.get_flags(item)
            if ida_bytes.is_code(F):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, item):
                    if ida_idp.is_call_insn(insn):
                        if insn.ops[0].type in [ida_ua.o_near, ida_ua.o_far]:
                            callees.append(insn.ops[0].addr)
    return list(dict.fromkeys(callees))

class hierarchy_t(abyss_filter_t):
    def finish_populating_widget_popup_ev(self, widget, popup_handle):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:

            class EAHandler(ida_kernwin.action_handler_t):
                def __init__(self, ea):
                    self.ea = ea
                    ida_kernwin.action_handler_t.__init__(self)

                def activate(self, ctx):
                    ida_kernwin.jumpto(self.ea)
                    return 1

                def update(self, ctx):
                    return ida_kernwin.AST_ENABLE_FOR_WIDGET

            class callees_t:
                def __init__(self, start_ea, max_recursion=MAX_DEPTH, max_func=MAX_FUNC):
                    self.ea = start_ea
                    name = ida_name.get_short_name(self.ea)
                    if not len(name):
                        name = "unkn_%x" % self.ea
                    self.base_path = "childs [%s]" % name
                    self.mr = max_recursion
                    self.mf = max_func
                    self.paths = {}
                    self._recurse(self.ea, self.base_path, 0)

                # TODO: check processing of recursive functions
                def _recurse(self, ea, path, depth):
                    if depth >= self.mr:
                        self.paths[path] = [("[...]", BADADDR)]
                        return

                    # for all callees of ea...
                    i = 0
                    for cea in Callees(ea):
                        if i+1 >= self.mf:
                            self.paths[path].append(("...", BADADDR))
                            break
                        loc_name = ida_name.get_short_name(cea)
                        if not len(loc_name):
                            loc_name = "unkn_%x" % cea
                        elem = (loc_name, cea)
                        # if path doesn't exist yet
                        if path not in self.paths:
                            self.paths[path] = [elem]
                        # if caller doesn't exist yet
                        if elem not in self.paths[path]:
                            self.paths[path].append(elem)
                            i += 1

                        newpath = "%s/%s" % (path, loc_name)
                        self._recurse(cea, newpath, depth+1)
                    return

            class callers_t:
                def __init__(self, start_ea, max_recursion=MAX_DEPTH, max_func=MAX_FUNC):
                    self.ea = start_ea
                    name = ida_name.get_short_name(self.ea)
                    if not len(name):
                        name = "unkn_%x" % self.ea
                    self.base_path = "parents [%s]" % name
                    self.mr = max_recursion
                    self.mf = max_func
                    self.paths = {}
                    self._recurse(self.ea, self.base_path , 0)

                # TODO: check processing of recursive functions
                def _recurse(self, ea, path, depth):
                    if depth+1 >= self.mr:
                        self.paths[path] = [("[...]", BADADDR)]
                        return

                    # for all callers of ea...
                    i = 0
                    for ref in idautils.CodeRefsTo(ea, False):
                        if i+1 >= self.mf:
                            self.paths[path].append(("...", BADADDR))
                            break
                        cea = ref
                        func = ida_funcs.get_func(cea)
                        if func:
                            cea = func.start_ea
                        loc_name = ida_name.get_short_name(cea)
                        if not len(loc_name):
                            loc_name = "unkn_%x" % cea
                        elem = (loc_name, cea)
                        # if path doesn't exist yet
                        if path not in self.paths:
                            self.paths[path] = [elem]
                        # if caller doesn't exist yet
                        if elem not in self.paths[path]:
                            self.paths[path].append(elem)
                            i += 1

                        newpath = "%s/%s" % (path, loc_name)
                        self._recurse(cea, newpath, depth+1)
                    return

            def build_menu(item_ea):
                callers = callers_t(item_ea)
                for path, info in callers.paths.items():
                    for loc_name, ea in info:
                        desc = ida_kernwin.action_desc_t(
                            "abyss:caller_%s_%s" % (path, loc_name),
                            "%s" % (loc_name),
                            EAHandler(ea),
                            None,
                            None,
                            41 if ea != BADADDR else -1)
                        ida_kernwin.attach_dynamic_action_to_popup(
                            widget,
                            popup_handle,
                            desc,
                            "%s (%d)/" % (path, len(info)),
                            ida_kernwin.SETMENU_APP)

                callees = callees_t(item_ea)
                for path, info in callees.paths.items():
                    for loc_name, ea in info:
                        desc = ida_kernwin.action_desc_t(
                            "abyss:callee_%s_%s" % (path, loc_name),
                            "%s" % (loc_name),
                            EAHandler(ea),
                            None,
                            None,
                            41 if ea != BADADDR else -1)
                        ida_kernwin.attach_dynamic_action_to_popup(
                            widget,
                            popup_handle,
                            desc,
                            "%s (%d)/" % (path, len(info)),
                            ida_kernwin.SETMENU_APP)

            ea = ida_kernwin.get_screen_ea()
            vu = ida_hexrays.get_widget_vdui(widget)
            if vu:
                if vu.get_current_item(ida_hexrays.USE_KEYBOARD):
                    if vu.item.it.is_expr() and vu.item.it.op is ida_hexrays.cot_obj:
                        _ea = vu.item.e.cexpr.obj_ea
                        if _ea != BADADDR:
                            ea = _ea
            build_menu(ea)

def FILTER_INIT():
    return hierarchy_t()
