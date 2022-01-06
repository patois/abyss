from abyss import abyss_filter_t
import ida_lines, ida_kernwin, ida_hexrays
from idaapi import BADADDR

COLOR = ida_kernwin.CK_EXTRA2

class vu_sync_t():
    def __init__(self, vu):
        self.vu = vu
        self.eadict = {}
        self._process()

    def __contains__(self, ea):
        return ea in self.eadict

    def get_items(self, ea):
        return self.eadict[ea]

    def _add_item(self, iea, ix, iy, ilen):
        if iea not in self.eadict:
            self.eadict[iea] = []
        si = (ix, iy, ilen)
        if si not in self.eadict[iea]:
            self.eadict[iea].append((ix, iy, ilen))
        return

    def _process(self):
        cf = self.vu.cfunc
        ci = ida_hexrays.ctree_item_t()
        ccode = cf.get_pseudocode()
        for ypos in range(cf.hdrlines, len(ccode)):
            tline = ccode.at(ypos).line
            # TODO: optimize the following loop
            idx = 0
            while idx < len(tline):
                citem_len = 0
                # get all items on a line
                if cf.get_line_item(tline, idx, True, None, ci, None):
                    iea = ci.it.ea
                    if iea != BADADDR:
                        # generate color-tagged/addr-tagged text of current item 
                        citem = ci.it.print1(None)
                        citem_len = len(ida_lines.tag_remove(citem))
                        # find (tagged) item text in current line
                        pos = tline.find(citem)
                        while pos != -1:
                            # calculate x position of item text in line
                            # by subtracting the number of color tag
                            # characters up to position "pos"
                            xpos = len(ida_lines.tag_remove(tline[:pos]))
                            self._add_item(iea, xpos, ypos, citem_len)                
                            pos = tline.find(citem, pos + citem_len)
                idx += ida_lines.tag_advance(tline[idx], 1)
        return

class item_sync_t(abyss_filter_t):
    """This plugin/filter highlights a decompiler view's
    citems that correspond to the current line ("screen ea")
    of a disassembly view.
    n.b.: experimental, untested and unoptimized code.

    Can be used alongside IDA's internal synchronization
    feature (although there may be coloring issues with
    colors cancelling out each others).

    This plugin uses the "Extra line background overlay #2"
    color from IDA's color options."""

    def __init__(self):
        abyss_filter_t.__init__(self)
        self.ea = ida_kernwin.get_screen_ea()
        self.funcs = {}

    def set_activated(self, val):
        if not val:
            # cleanup if filter is about to be deactivated
            self.funcs = {}
        return super().set_activated(val)

    def refresh_pseudocode_ev(self, vu):
        entry_ea = vu.cfunc.entry_ea
        self.funcs[entry_ea] = vu_sync_t(vu)
        return

    def screen_ea_changed_ev(self, ea, prev_ea):
        w = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_DISASM:
            self.ea = ea
            # why does refresh_idaview_anyway() work but request_refresh() doesn't?
            #ida_kernwin.clear_refresh_request(ida_kernwin.IWID_PSEUDOCODE)
            #ida_kernwin.request_refresh(ida_kernwin.IWID_PSEUDOCODE, True)
            ida_kernwin.refresh_idaview_anyway()
        return

    def get_lines_rendering_info_ev(self, out, widget, rin):
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        vu = ida_hexrays.get_widget_vdui(widget)
        if vu:
            cf = vu.cfunc
            if cf.entry_ea not in self.funcs:
                return

            vusync = self.funcs[cf.entry_ea]
            ea = self.ea
            if ea in vusync:
                slist = vusync.get_items(ea)
                for section_lines in rin.sections_lines:
                    for line in section_lines:
                        lnnum = ida_kernwin.place_t.as_simpleline_place_t(line.at).n
                        for sync_info in slist:
                            ix, iy, ilen = sync_info
                            if lnnum == iy:
                                e = ida_kernwin.line_rendering_output_entry_t(line)
                                e.bg_color = COLOR
                                e.cpx = ix
                                e.nchars = ilen
                                e.flags |= ida_kernwin.LROEF_CPS_RANGE
                                out.entries.push_back(e)
        return

def FILTER_INIT():
    return item_sync_t()