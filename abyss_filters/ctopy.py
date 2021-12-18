from abyss import abyss_filter_t
import ida_lines, ida_kernwin
import sys, re

# experimental code cloned from https://github.com/pfalcon/ctopy

"""
ctopy -- a quick and dirty C-to-Python translator.

Libraries not mapped that theoretically could be: curses.panel, dbm,
md5, popen2, pty, resource, sha, subprocess, syslog, time.  Some of these
would need more elaborate machinery for method translation.

Python library bindings are as of 2.6a0.
"""
debug = 0
stringify = []

printflike = ["printf", "sprintf", "vfprintf",
              "printw", "mvprintw", "wprintw", "mvwprintw"]

types = ["void", "int", "bool", "char", "short", "double", "long", "float",
         "time_t", "FILE", "WINDOW", "uint8_t", "uint16_t", "uint32_t"]

shorthands = {
    'id' : r"[a-zA-Z_][a-zA-Z0-9._]*",
    'exp' : r"[a-zA-Z0-9._\-+\*/]+",
    'type' : r"\b" + r"\b|\b".join(types) + r"\b",
    'class' : r"\b__dummyclass__\b",
    'ind' : r"(\n[ \t]*)",      # Whitespace at start of line
    'eol' : r"[ \t]*(?=\n|\Z)",     # Whitespace to end of line or comment
    'arg' : r"([^,]+),\s*",     # initial or medial argument
    'farg' : r"([^)]+)",        # final argument
}

# C functions and constants to be mapped into Python standard library bindings.
funmappings = (
    # File object methods (from C stdlib).
    (r"\bfclose\(%(farg)s\)", r"\1.close()", None),
    (r"\bfflush\(%(farg)s\)", r"\1.flush()", None),
    (r"\bfileno\(%(farg)s\)", r"\1.fileno()", None),
    (r"\bfprintf\(%(arg)s\)", r"\1.write()", None),
    (r"\bfseek\(%(arg)s", r"\1.seek(", None),
    (r"\bftell\(%(farg)s\)", r"\1.tell()", None),
    (r"\bftruncate\(%(arg)s", r"\1.truncate(", None),
    # Python atexit library
    (r"\batexit\(", r"atexit.register(", "atexit"),
    # Python crypt library
    (r"\bcrypt\(", r"crypt.crypt(", "crypt"),
    # Curses library.  Below are all function calls listed in the
    # ncurses(3) version 5.5 manual page in the order they are listed.
    # The ones we don't translate have been left in as comments,
    # pending future improvements.  The largest category of things not
    # translated is the wide-character support; it's possible there's
    # an easy way to map this, but I don't have a need for it.
    # Mappings marked "EXCEPTION" violate the convention that the C names
    # of window methods begin with 'w'. Mappings marked "NONTRIVIAL"
    # map a C entry point into a Python entry point with a different name,
    # usually to throw away a length argument Python doesn't need or vecause
    # the Python method handles a position as the first two arguments.
    (r"\bCOLOR_PAIR\(", "curses.color_pair(", "curses"),
    (r"\bPAIR_NUMBER\(", "curses.pair_number(", "curses"),
    #_nc_tracebits           curs_trace(3X)*
    #_traceattr              curs_trace(3X)*
    #_traceattr2             curs_trace(3X)*
    #_tracechar              curs_trace(3X)*
    #_tracechtype            curs_trace(3X)*
    #_tracechtype2           curs_trace(3X)*
    #_tracedump              curs_trace(3X)*
    #_tracef                 curs_trace(3X)*
    #_tracemouse             curs_trace(3X)*
    #add_wch                 curs_add_wch(3X)
    #add_wchnstr             curs_add_wchstr(3X)
    #add_wchstr              curs_add_wchstr(3X)
    (r"\baddch\(", r"stdscr.addch(", "curses"),
    #addchnstr               curs_addchstr(3X)
    #addchstr                curs_addchstr(3X)
    (r"\baddnstr\(", r"stdscr.addnstr(", "curses"),
    #addnwstr                curs_addwstr(3X)
    (r"\baddstr\(", r"stdscr.addstr(", "curses"),
    #addwstr                 curs_addwstr(3X)
    #assume_default_colors   default_colors(3X)*
    #attr_get                curs_attr(3X)
    (r"\battr_off\(", r"stdscr.attrof(", r"curses"),
    (r"\battr_on\(", r"stdscr.attron(", r"curses"),
    (r"\battr_set\(", r"stdscr.attrset(", r"curses"),
    (r"\battroff\(", r"stdscr.attrof(", r"curses"),
    (r"\battron\(", r"stdscr.attron(", r"curses"),
    (r"\battrset\(", r"stdscr.attrset(", r"curses"),
    (r"\bbaudrate\(", r"curses.baudrate(", r"curses"),
    (r"\bbeep\(", r"curses.beep(", r"curses"),
    (r"\bbkgd\(", r"stdscr.bkgd(", r"curses"),
    (r"\bbkgdset\(", r"stsdcr.bkgdset(", r"curses"),
    #bkgrnd                  curs_bkgrnd(3X)
    #bkgrndset               curs_bkgrnd(3X)
    (r"\bborder\(", r"stdscr.border(", r"curses"), 
    #border_set              curs_border_set(3X)
    (r"\bbox\(%(arg)s", r"\1.box(", r"curses"),     # EXCEPTION
    #box_set                 curs_border_set(3X)
    (r"\bcan_change_color\(", r"curses.can_change_color(", r"curses"),
    (r"\bcbreak\(", r"curses.cbreak(", r"curses"),
    #chgat                   curs_attr(3X)
    (r"\bclear\(", r"stdscr.clear(", r"curses"),
    (r"\bclearok\(", r"stdscr.clearok(", r"curses"),
    (r"\bclrtobot\(", r"stdscr.clrtobot(", r"curses"),
    (r"\bclrtoeol\(", r"stdscr.clrtoeol(", r"curses"),
    (r"\bcolor_content\(", r"curses.color_content(", r"curses"),
    #color_set               curs_attr(3X)
    #copywin                 curs_overlay(3X)
    (r"\bcurs_set\(", r"curses.curs_set(", r"curses"),
    #curses_version          curs_extend(3X)*
    (r"\bdef_prog_mode\(", r"curses.def_prog_mode(", r"curses"),
    (r"\bdef_shell_mode\(", r"curses.def_shell_mode(", r"curses"),
    #define_key              define_key(3X)*
    #del_curterm             curs_terminfo(3X)
    (r"\bdelay_output\(", r"curses.delay_output(", r"curses"),
    (r"\bdelch\(", r"stdscr.delch(", r"curses"),
    (r"\bdeleteln\(\)", r"stdscr.deleteln()", r"curses"),
    #delscreen               curs_initscr(3X)
    #delwin                  curs_window(3X)
    (r"\bderwin\(%(arg)s", r"\1.derwin(", "curses"),        # EXCEPTION
    (r"\bdoupdate\(\)", r"curses.doupdate()", "curses"),
    #dupwin                  curs_window(3X)
    (r"\becho\(", r"curses.echo(", "curses"),
    #echo_wchar              curs_add_wch(3X)
    (r"\bechochar\(", r"stdscr.echochar(", "curses"),
    (r"\bendwin\(", r"curses.endwin(", "curses"),
    (r"\berase\(", r"stdscr.erase(", "curses"),
    #erasechar               curs_termattrs(3X)
    #erasewchar              curs_termattrs(3X)
    (r"\bfilter\(\)", r"curses.filter()", "curses"),
    (r"\bflash\(\)", r"curses.flash()", "curses"),
    (r"\bflushinp\(\)", r"curses.flushinp()", "curses"),
    #get_wch                 curs_get_wch(3X)
    #get_wstr                curs_get_wstr(3X)
    (r"\bgetbegyx\(%(arg)s%(arg)s%(farg)s\)",       # EXCEPTION
     r"(\2, \3) = \1.getbegyx()", "curses"),
    (r"\bgetbkgd\(", r"\1.getbkgd(", "curses"),     # EXCEPTION
    #getbkgrnd               curs_bkgrnd(3X)
    #getcchar                curs_getcchar(3X)
    (r"\bgetch\(", r"stdscr.getch(", "curses"),
    (r"\bgetmaxyx\(%(arg)s", r"\1.getmaxyx(", "curses"),    # EXCEPTION
    (r"\bgetmouse\(%(farg)s\)", r"\1 = curses.getmouse()", "curses"),
    #getn_wstr               curs_get_wstr(3X)
    (r"\bgetnstr\(%(arg)s%(farg)s\)",   # NONTRIVIAL
     r"\1 = stdscr.getstr()", "curses"),
    (r"\bgetparyx\(%(arg)s%(arg)s%(farg)s\)",   # EXCEPTION
     r"(\2, \3) = \1.getparyx()", "curses"),
    (r"\bgetsyx\(%(arg)s%(farg)s\)", r"(\1, \2) = curses.getsyx()", "curses"),
    (r"\bgetstr\(\)", r"stdscr.getstr()", "curses"),
    (r"\bgetyx\(%(arg)s%(arg)s%(farg)s\)",      #EXCEPTION
     r"(\2, \3) = \1.getyx()", "curses"),
    (r"\bgetwin\(", r"curses.getwin(", "curses"),
    (r"\bhalfdelay\(", r"curses.halfdelay(", "curses"),
    (r"\bhas_colors\(", r"curses.has_colors(", "curses"),
    (r"\bhas_ic\(", r"curses.has_ic(", "curses"),
    (r"\bhas_il\(", r"curses.has_il(", "curses"),
    (r"\bhas_key\(", r"curses.has_key(", "curses"),
    (r"\bhline\(", r"stdscr.hline(", "curses"),
    #hline_set               curs_border_set(3X)
    (r"\bidcok\(%(arg)s", r"\1.idcok(", "curses"),  # EXCEPTION
    (r"\bidlok\(%(arg)s", r"\1.idlok(", "curses"),  # EXCEPTION
    (r"\bimmedok\(%(arg)s", r"\1.immedok(", "curses"),  # EXCEPTION
    # in_wch                  curs_in_wch(3X)
    # in_wchnstr              curs_in_wchstr(3X)
    # in_wchstr               curs_in_wchstr(3X)
    (r"\binch\(", r"stdscr.inch(", "curses"),
    #inchnstr                curs_inchstr(3X)
    #inchstr                 curs_inchstr(3X)
    (r"\binit_color\(", r"curses.init_color(", "curses"),
    (r"\binit_pair\(", r"curses.init_pair(", "curses"),
    (r"\binitscr\(", r"curses.initscr(", "curses"),
    (r"\binnstr\(%(arg)s", r"\1.instr(", "curses"), # NONTRIVIAL
    #innwstr                 curs_inwstr(3X)
    #ins_nwstr               curs_ins_wstr(3X)
    #ins_wch                 curs_ins_wch(3X)
    #ins_wstr                curs_ins_wstr(3X)
    (r"\binsch\(", r"stdscr.insch(", "curses"),
    (r"\binsdelln\(", r"stdscr.insdelln(", "curses"),
    (r"\binsertln\(", r"stdscr.insertln(", "curses"),
    (r"\binsnstr\(", r"stdscr.insnstr(", "curses"),
    (r"\binsstr\(", r"stdscr.insstr(", "curses"),
    (r"\binstr\(%(farg)s\)", r"\1 = stdscr.instr()", "curses"),
    (r"\bintrflush\(\)", r"curses.intrflush()", "curses"),
    #inwstr                  curs_inwstr(3X)
    (r"\bis_linetouched\(%(arg)s", r"\1.is_linetouched(", "curses"),# EXCEPTION
    (r"\bis_wintouched\(%(farg)s\)", r"\1.is_wintouched()", "curses"),# EXCEPTION
    (r"\bisendwin\(\)", r"curses.isendwin()", "curses"),
    #key_defined             key_defined(3X)*
    #key_name                 curs_util(3X)
    #keybound                keybound(3X)*
    (r"\bkeyname\(", r"curses.keyname(", "curses"),
    #keyok                   keyok(3X)*
    (r"\bkeypad\(%(arg)s", r"\1.keypad(", "curses"),    # EXCEPTION
    (r"\bkillchar\(\)", r"curses.killchar()", "curses"),
    #killwchar               curs_termattrs(3X)
    (r"\bleaveok\(%(arg)s", r"\1.leaveok(", "curses"),  # EXCEPTION
    (r"\blongname\(\)", r"curses.longname()", "curses"),
    #mcprint                 curs_print(3X)*
    (r"\bmeta\(", r"curses.meta(", "curses"),
    #mouse_trafo             curs_mouse(3X)*
    (r"\bmouseinterval\(", r"curses.mouseinterval(", "curses"),
    (r"\bmousemask\(", r"curses.mousemask(", "curses"),
    (r"\bmove\(", r"stdscr.move(", "curses"),
    #mvadd_wch               curs_add_wch(3X)
    #mvadd_wchnstr           curs_add_wchstr(3X)
    #mvadd_wchstr            curs_add_wchstr(3X)
    (r"\bmvaddch\(", r"stdscr.addch(", "curses"),   # NONTRIVIAL
    #mvaddchnstr             curs_addchstr(3X)
    #mvaddchstr              curs_addchstr(3X)
    (r"\bmvaddnstr\(", r"stdscr.addnstr(", "curses"),   # NONTRIVIAL
    #mvaddnwstr              curs_addwstr(3X)
    (r"\bmvaddstr\(", r"stdscr.addstr(", "curses"), # NONTRIVIAL
    #mvaddwstr               curs_addwstr(3X)
    #mvchgat                 curs_attr(3X)
    #mvcur                   curs_terminfo(3X)
    (r"\bmvdelch\(", r"stdscr.delch(", "curses"),   # NONTRIVIAL
    (r"\bmvderwin\(%(arg)s", r"\1.derwin(", "curses"),  # NONTRIVIAL,EXCEPTION
    #mvget_wch               curs_get_wch(3X)
    #mvget_wstr              curs_get_wstr(3X)
    (r"\bmvgetch\(%(arg)s", r"stdscr.getch(", "curses"),    # NONTRIVIAL
    #mvgetn_wstr             curs_get_wstr(3X)
    (r"\bmvgetnstr\(%(arg)s%(arg)s%(arg)s%(farg)s\)",       # NONTRIVIAL
     r"\3 = stdscr.getstr(\1, \2)", "curses"),
    (r"\bmvgetstr\(%(arg)s%(arg)s%(farg)s\)",       # NONTRIVIAL
     r"\3 = stdscr.getstr(\1, \2)", "curses"),
    (r"\bmvhline\(", r"stdscr.hline(", "curses"),   # NONTRIVIAL
    #mvhline_set             curs_border_set(3X)
    #mvin_wch                curs_in_wch(3X)
    #mvin_wchnstr            curs_in_wchstr(3X)
    #mvin_wchstr             curs_in_wchstr(3X)
    (r"\bmvinch\(", r"stdscr.inch(", "curses"),     # NONTRIVIAL
    (r"\bmvinchnstr\(", r"stdscr.instr(", "curses"),    # NONTRIVIAL
    (r"\bmvinchstr\(", r"stdscr.instr(", "curses"), # NONTRIVIAL
    (r"\bmvinnstr\(", r"stdscr.instr(", "curses"),  # NONTRIVIAL
    #mvinnwstr               curs_inwstr(3X)
    #mvins_nwstr             curs_ins_wstr(3X)
    #mvins_wch               curs_ins_wch(3X)
    #mvins_wstr              curs_ins_wstr(3X)
    (r"\bmvinsch\(", r"stdscr.insch(", "curses"),   # NONTRIVIAL
    (r"\bmvinsnstr\(", r"stdscr.instr(", "curses"), # NONTRIVIAL
    (r"\bmvinsstr\(", r"stdscr.instr(", "curses"),  # NONTRIVIAL
    (r"\bmvinstr\(", r"stdscr.instr(", "curses"),   # NONTRIVIAL
    #mvwinwstr               curs_inwstr(3X)
    (r"\bmvprintw\(", r"stdscr.addstr(", "curses"), # NONTRIVIAL
    # mvscanw                 curs_scanw(3X)
    (r"\bmvvline\(", r"stdscr.vline(", "curses"),   # NONTRIVIAL
    #mvvline_set             curs_border_set(3X)
    #mvwadd_wch              curs_add_wch(3X)
    #mvwadd_wchnstr          curs_add_wchstr(3X)
    #mvwadd_wchstr           curs_add_wchstr(3X)
    (r"\bmvwaddch\(%(arg)s", r"\1.addch(", "curses"),   # NONTRIVIAL
    #mvwaddchnstr            curs_addchstr(3X)
    #mvwaddchstr             curs_addchstr(3X)
    (r"\bmvwaddnstr\(%(arg)s", r"\1.addnstr(", "curses"),   # NONTRIVIAL
    #mvwaddnwstr             curs_addwstr(3X)
    (r"\bmvwaddstr\(%(arg)s", r"\1.addstr(", "curses"), # NONTRIVIAL
    #mvwaddwstr              curs_addwstr(3X)
    #mvwchgat                curs_attr(3X)
    (r"\bmvwdelch\(%(arg)s", r"\1.delch(", "curses"),   # NONTRIVIAL
    #mvwget_wch              curs_get_wch(3X)
    #mvwget_wstr             curs_get_wstr(3X)
    (r"\bmvwgetch\(%(arg)s", r"\1.getch(", "curses"),   # NONTRIVIAL
    #mvwgetn_wstr            curs_get_wstr(3X)
    (r"\bmvwgetnstr\(%(arg)s", r"\1.getstr(", "curses"),    # NONTRIVIAL
    (r"\bmvwgetstr\(%(arg)s", r"\1.getstr(", "curses"), # NONTRIVIAL
    (r"\bmvwhline\(%(arg)s", r"\1.hline(", "curses"),   # NONTRIVIAL
    #mvwhline_set            curs_border_set(3X)
    (r"\bmvwin\(%(arg)s", r"\1.mvwin(", "curses"),  # EXCEPTION
    #mvwin_wch               curs_in_wch(3X)
    #mvwin_wchnstr           curs_in_wchstr(3X)
    #mvwin_wchstr            curs_in_wchstr(3X)
    (r"\bmvwinch\(%(arg)s", r"\1.inch(", "curses"), # NONTRIVIAL
    #mvwinchnstr             curs_inchstr(3X)
    #mvwinchstr              curs_inchstr(3X)
    (r"\bmvwinnstr\(%(arg)s%(arg)s%(arg)s", # NONTRIVIAL
     r"\3 = \1.instr(\1, \2", "curses"),
    #mvwinnwstr              curs_inwstr(3X)
    #mvwins_nwstr            curs_ins_wstr(3X)
    #mvwins_wch              curs_ins_wch(3X)
    #mvwins_wstr             curs_ins_wstr(3X)
    (r"\bmvwinsch\(%(arg)s", r"\1.insch(", "curses"),   # NONTRIVIAL
    (r"\bmvwinsnstr\(%(arg)s", r"\1.insnstr(", "curses"),   # NONTRIVIAL
    (r"\bmvwinsstr\(%(arg)s", r"\1.insstr(", "curses"), # NONTRIVIAL
    (r"\bmvwinstr\(%(arg)s", r"\1.instr(", "curses"),   # NONTRIVIAL
    #mvwinwstr               curs_inwstr(3X)
    (r"\bmvwprintw\(%(arg)s", r"\1.addstr(", "curses"), # NONTRIVIAL
    #mvwscanw                curs_scanw(3X)
    (r"\bmvwvline\(%(arg)s", r"\1.vline(", "curses"),   # NONTRIVIAL
    #mvwvline_set            curs_border_set(3X)
    (r"\bnapms\(", r"curses.napms(", "curses"),
    (r"\bnewpad\(", r"curses.newpad(", "curses"),
    #newterm                 curs_initscr(3X)
    (r"\bnewwin\(", r"curses.newwin(", "curses"),
    (r"\bnl\(", r"curses.nl(", "curses"),
    (r"\bnocbreak\(", r"curses.nocbreak(", "curses"),
    (r"\bnodelay\(%(arg)s", r"\1.nodelay(", "curses"),  # EXCEPTION
    (r"\bnoecho\(", r"curses.noecho(", "curses"),
    (r"\bnonl\(", r"curses.nonl(", "curses"),
    (r"\bnoqiflush\(", r"curses.noqiflush(", "curses"),
    (r"\bnoraw\(", r"curses.noraw(", "curses"),
    (r"\bnotimeout\(%(arg)s", r"\1.notimeout(", "curses"),
    (r"\boverlay\(%(arg)s", r"\1.overlay(", "curses"),
    (r"\boverwrite\(%(arg)s", r"\1.overwrite(", "curses"),
    (r"\bpair_content\(", r"curses.pair_content(", "curses"),
    #pechochar               curs_pad(3X)
    #pnoutrefresh            curs_pad(3X)
    #prefresh                curs_pad(3X)
    (r"\bprintw\(%(arg)s", r"\1.addstr(", "curses"),    # NONTRIVIAL
    #putp                    curs_terminfo(3X)
    #putwin                  curs_util(3X)
    (r"\bqiflush\(", r"curses.qiflush(", "curses"),
    (r"\braw\(", r"curses.raw(", "curses"),
    (r"\bredrawwin\(%(farg)s\)", r"\1.redrawwin()", "curses"),  # EXCEPTION
    (r"\brefresh\(\)", r"stdscr.refresh()", "curses"),
    (r"\breset_prog_mode\(", r"curses.reset_prog_mode(", "curses"),
    (r"\breset_shell_mode\(", r"curses.reset_shell_mode(", "curses"),
    #resetty                 curs_kernel(3X)
    #resizeterm              resizeterm(3X)*
    #restartterm             curs_terminfo(3X)
    #ripoffline              curs_kernel(3X)
    #savetty                 curs_kernel(3X)
    #scanw                   curs_scanw(3X)
    #scr_dump                curs_scr_dump(3X)
    #scr_init                curs_scr_dump(3X)
    #scr_restore             curs_scr_dump(3X)
    #scr_set                 curs_scr_dump(3X)
    (r"\bscrl\(", r"stdscr.scroll(", "curses"), # NONTRIVIAL
    (r"\bscroll\(%(farg)s\)", r"\1.scroll(1)", "curses"),   # NONTRIVIAL
    (r"\bscrollok\(%(arg)s", r"\1.scrollok(", "curses"),    # EXCEPTION
    #set_curterm             curs_terminfo(3X)
    #set_term                curs_initscr(3X)
    #setcchar                curs_getcchar(3X)
    (r"\bsetscrreg\(", r"stdscr.setscrreg(", "curses"),
    (r"\bsetsyx\(", r"curses.setsyx(", "curses"),
    #setterm                 curs_terminfo(3X)
    (r"\bsetupterm\(", r"curses.setupterm(", "curses"),
    #slk_attr                curs_slk(3X)*
    #slk_attr_off            curs_slk(3X)
    #slk_attr_on             curs_slk(3X)
    #slk_attr_set            curs_slk(3X)
    #slk_attroff             curs_slk(3X)
    #slk_attron              curs_slk(3X)
    #slk_attrset             curs_slk(3X)
    #slk_clear               curs_slk(3X)
    #slk_color               curs_slk(3X)
    #slk_init                curs_slk(3X)
    #slk_label               curs_slk(3X)
    #slk_noutrefresh         curs_slk(3X)
    #slk_refresh             curs_slk(3X)
    #slk_restore             curs_slk(3X)
    #slk_set                 curs_slk(3X)
    #slk_touch               curs_slk(3X)
    (r"\bstandend\(", r"stdscr.standend(", "curses"),
    (r"\bstandout\(", r"stdscr.standout(", "curses"),
    (r"\bstart_color\(", r"curses.start_color(", "curses"),
    (r"\bsubpad\(%(arg)s", r"\1.subpad(", "curses"),    # EXCEPTION
    (r"\bsubwin\(%(arg)s", r"\1.subwin(", "curses"),    # EXCEPTION
    (r"\bsyncok\(%(arg)s", r"\1.syncok(", "curses"),    # EXCEPTION
    #term_attrs              curs_termattrs(3X)
    (r"\btermattrs\(", r"curses.termattrs(", "curses"),
    (r"\btermname\(", r"curses.termname(", "curses"),
    #tgetent                 curs_termcap(3X)
    #tgetflag                curs_termcap(3X)
    #tgetnum                 curs_termcap(3X)
    #tgetstr                 curs_termcap(3X)
    #tgoto                   curs_termcap(3X)
    (r"\btigetflag\(", r"curses.tigetflag(", "curses"),
    (r"\btigetnum\(", r"curses.tigetnum(", "curses"),
    (r"\btigetstr\(", r"curses.tigetstr(", "curses"),
    (r"\btimeout\(", r"stdscr.timeout(", "curses"),
    (r"\btouchline\(%(arg)s", r"\1.touchline(", "curses"),  # EXCEPTION
    (r"\btouchwin\(%(farg)s\)", r"\1.touchwin()", "curses"),    # EXCEPTION
    (r"\btparm\(", r"curses.tparm(", "curses"),
    #tputs                   curs_termcap(3X)
    #tputs                   curs_terminfo(3X)
    #trace                   curs_trace(3X)*
    (r"\btypeahead\(", r"curses.typeahead(", "curses"),
    (r"\bunctrl\(", r"curses.unctrl(", "curses"),
    #unget_wch               curs_get_wch(3X)
    (r"\bungetch\(", r"curses.ungetch(", "curses"),
    (r"\bungetmouse\(%(arg)s", r"\1.ungetmouse(", "curses"),    # False friend
    (r"\buntouchwin\(%(farg)s\)", r"\1.untouchwin()", "curses"),
    (r"\buse_default_colors\(", r"curses.use_default_colors(", "curses"),
    (r"use_env\(", r"use_env(", "curses"),
    #use_extended_names      curs_extend(3X)*
    #vid_attr                curs_terminfo(3X)
    #vid_puts                curs_terminfo(3X)
    #vidattr                 curs_terminfo(3X)
    #vidputs                 curs_terminfo(3X)
    (r"vline\(", "stdscr.vline(", "curses"),
    #vline_set               curs_border_set(3X)
    #vw_printw               curs_printw(3X)
    #vw_scanw                curs_scanw(3X)
    #vwprintw                curs_printw(3X)
    #vwscanw                 curs_scanw(3X)
    #wadd_wch                curs_add_wch(3X)
    #wadd_wchnstr            curs_add_wchstr(3X)
    #wadd_wchstr             curs_add_wchstr(3X)
    (r"\bwaddch\(%(arg)s", "\1.addch(", "curses"),  # NONTRIVIAL
    #waddchnstr              curs_addchstr(3X)
    #waddchstr               curs_addchstr(3X)
    (r"\bwaddnstr\(%(arg)s", "\1.addnstr(", "curses"),  # NONTRIVIAL
    #waddnwstr               curs_addwstr(3X)
    (r"\bwaddstr\(%(arg)s", "\1.addstr(", "curses"),    # NONTRIVIAL
    #waddwstr                curs_addwstr(3X)
    #wattr_get               curs_attr(3X)
    #wattr_off               curs_attr(3X)
    #wattr_on                curs_attr(3X)
    #wattr_set               curs_attr(3X)
    (r"\bwattroff\(%(arg)s", "\1.attroff(", "curses"),  # NONTRIVIAL
    (r"\bwattron\(%(arg)s", "\1.attron(", "curses"),    # NONTRIVIAL
    (r"\bwattrset\(%(arg)s", "\1.attrset(", "curses"),  # NONTRIVIAL
    (r"\bwbkgd\(%(arg)s", "\1.bkgd(", "curses"),    # NONTRIVIAL
    (r"\bwbkgdset\(%(arg)s", "\1.bkgdset(", "curses"),  # NONTRIVIAL
    #wbkgrnd                 curs_bkgrnd(3X)
    #wbkgrndset              curs_bkgrnd(3X)
    (r"\bwborder\(%(arg)s", "\1.border(", "curses"),    # NONTRIVIAL
    #wborder_set             curs_border_set(3X)
    #wchgat                  curs_attr(3X)
    (r"\bwclear\(%(farg)s\)", "\1.clear()", "curses"),  # NONTRIVIAL
    (r"\bwclrtobot\(%(farg)s\)", "\1.clrtobot()", "curses"),    # NONTRIVIAL
    (r"\bwclrtoeol\(%(farg)s\)", "\1.clrtoeol()", "curses"),    # NONTRIVIAL
    #wcolor_set              curs_attr(3X)
    #wcursyncup              curs_window(3X)
    (r"\bwdelch\(%(arg)s", "\1.delch(", "curses"),  # NONTRIVIAL
    (r"\bwdeleteln\(%(farg)s\)", "\1.deleteln()", "curses"),    # NONTRIVIAL
    #wecho_wchar             curs_add_wch(3X)
    (r"\bwechochar\(%(arg)s", "\1.echochar(", "curses"),    # NONTRIVIAL
    (r"\bwenclose\(%(arg)s", "\1.enclose(", "curses"),  # NONTRIVIAL
    (r"\bwerase\(%(farg)s\)", "\1.erase()", "curses"),  # NONTRIVIAL
    #wget_wch                curs_get_wch(3X)
    #wget_wstr               curs_get_wstr(3X)
    #wgetbkgrnd              curs_bkgrnd(3X)
    (r"\bwgetch\(%(farg)s\)", "\1.getch()", "curses"),  # NONTRIVIAL
    #wgetn_wstr              curs_get_wstr(3X)
    (r"\bwgetnstr\(%(arg)s", "\1.getstr(", "curses"),   # NONTRIVIAL
    (r"\bwgetstr\(%(arg)s", "\1.getstr(", "curses"),    # NONTRIVIAL
    (r"\bwhline\(%(arg)s", "\1.hline(", "curses"),  # NONTRIVIAL
    #whline_set              curs_border_set(3X)
    #win_wch                 curs_in_wch(3X)
    #win_wchnstr             curs_in_wchstr(3X)
    #win_wchstr              curs_in_wchstr(3X)
    (r"\bwinch\(%(arg)s", "\1.inch(", "curses"),    # NONTRIVIAL
    #winchnstr               curs_inchstr(3X)
    #winchstr                curs_inchstr(3X)
    (r"\bwinnstr\(%(arg)s", "\1.instr(", "curses"), # NONTRIVIAL
    #winnwstr                curs_inwstr(3X)
    #wins_nwstr              curs_ins_wstr(3X)
    #wins_wch                curs_ins_wch(3X)
    #wins_wstr               curs_ins_wstr(3X)
    (r"\bwinsch\(%(arg)s", "\1.insch(", "curses"),  # NONTRIVIAL
    (r"\bwinsdelln\(%(arg)s", "\1.insdelln(", "curses"),    # NONTRIVIAL
    (r"\bwinsertln\(%(farg)s\)", "\1.insertln()", "curses"),    # NONTRIVIAL
    (r"\bwinsnstr\(%(arg)s", "\1.insnstr(", "curses"),  # NONTRIVIAL
    (r"\binsstr\(%(arg)s", "\1.insstr(", "curses"), # NONTRIVIAL
    (r"\bwinstr\(%(arg)s", "\1.instr(", "curses"),  # NONTRIVIAL
    #winwstr                 curs_inwstr(3X)
    #wmouse_trafo            curs_mouse(3X)*
    (r"\bwmove\(%(arg)s", "\1.move(", "curses"),    # NONTRIVIAL
    (r"\bwnoutrefresh\(%(arg)s", "\1.noutrefresh(", "curses"),  # NONTRIVIAL
    (r"\bwprintw\(%(arg)s", "\1.addstr(", "curses"),    # NONTRIVIAL
    (r"\bwredrawln\(%(arg)s", "\1.redrawln(", "curses"),    # NONTRIVIAL
    (r"\bwrefresh\(%(arg)s", "\1.refresh(", "curses"),  # NONTRIVIAL
    (r"\bwresize\(%(arg)s", "\1.resize(", "curses"),    # NONTRIVIAL
    #wscanw                  curs_scanw(3X)
    (r"\bwscrl\(%(arg)s", r"\1.scroll(", "curses"), # NINTRIVIAL
    (r"\bwsetscrreg\(%(arg)s", "\1.setscrreg(", "curses"),  # NONTRIVIAL
    (r"\bwstandend\(%(arg)s", "\1.standend(", "curses"),    # NONTRIVIAL
    (r"\bwstandout\(%(arg)s", "\1.standout(", "curses"),    # NONTRIVIAL
    (r"\bwsyncdown\(%(farg)s\)", "\1.syncdown()", "curses"),    # NONTRIVIAL
    (r"\bwsyncup\(%(arg)s", "\1.syncup(", "curses"),    # NONTRIVIAL
    (r"\bwtimeout\(%(arg)s", "\1.timeout(", "curses"),  # NONTRIVIAL
    (r"\bwtouchln\(%(arg)s", "\1.touchln(", "curses"),  # NONTRIVIAL
    (r"\bwunctrl\(%(arg)s", r"\1.unctrl(", "curses"),   # NONTRIVIAL
    (r"\bwvline\(%(arg)s", r"\1.vline(", "curses"), # NONTRIVIAL
    #wvline_set              curs_border_set(3X)
    # And this does the curses library constants
    (r"\bA_ATTRIBUTES\b", r"curses.A_ATTRIBUTES", "curses"),
    (r"\bA_NORMAL\b", r"curses.A_NORMAL", "curses"),
    (r"\bA_STANDOUT\b", r"curses.A_STANDOUT", "curses"),
    (r"\bA_UNDERLINE\b", r"curses.A_UNDERLINE", "curses"),
    (r"\bA_REVERSE\b", r"curses.A_REVERSE", "curses"),
    (r"\bA_BLINK\b", r"curses.A_BLINK", "curses"),
    (r"\bA_DIM\b", r"curses.A_DIM", "curses"),
    (r"\bA_BOLDW\b", r"curses.A_BOLDW", "curses"),
    (r"\bA_ALTCHARSET\b", r"curses.A_ALTCHARSET", "curses"),
    (r"\bA_INVIS\b", r"curses.A_INVIS", "curses"),
    (r"\bA_PROTECT\b", r"curses.A_PROTECT", "curses"),
    (r"\bA_HORIZONTAL\b", r"curses.A_HORIZONTAL", "curses"),
    (r"\bA_LEFT\b", r"curses.A_LEFT", "curses"),
    (r"\bA_LOW\b", r"curses.A_LOW", "curses"),
    (r"\bA_RIGHT\b", r"curses.A_RIGHT", "curses"),
    (r"\bA_TOP\b", r"curses.A_TOP", "curses"),
    (r"\bA_VERTICAL\b", r"curses.A_VERTICAL", "curses"),
    (r"\bOLOR_BLACK\b", r"curses.OLOR_BLACK", "curses"),
    (r"\bOLOR_RED\b", r"curses.OLOR_RED", "curses"),
    (r"\bOLOR_GREEN\b", r"curses.OLOR_GREEN", "curses"),
    (r"\bOLOR_YELLOW\b", r"curses.OLOR_YELLOW", "curses"),
    (r"\bOLOR_BLUE\b", r"curses.OLOR_BLUE", "curses"),
    (r"\bOLOR_MAGENTA\b", r"curses.OLOR_MAGENTA", "curses"),
    (r"\bOLOR_CYAN\b", r"curses.OLOR_CYAN", "curses"),
    (r"\bOLOR_WHITE\b", r"curses.OLOR_WHITE", "curses"),
    (r"\bACS_ULCORNER\b", r"curses.ACS_ULCORNER", "curses"),
    (r"\bACS_LLCORNER\b", r"curses.ACS_LLCORNER", "curses"),
    (r"\bACS_URCORNER\b", r"curses.ACS_URCORNER", "curses"),
    (r"\bACS_LRCORNER\b", r"curses.ACS_LRCORNER", "curses"),
    (r"\bACS_LTEE\b", r"curses.ACS_LTEE", "curses"),
    (r"\bACS_RTEE\b", r"curses.ACS_RTEE", "curses"),
    (r"\bACS_BTEE\b", r"curses.ACS_BTEE", "curses"),
    (r"\bACS_TTEE\b", r"curses.ACS_TTEE", "curses"),
    (r"\bACS_HLINE\b", r"curses.ACS_HLINE", "curses"),
    (r"\bACS_VLINE\b", r"curses.ACS_VLINE", "curses"),
    (r"\bACS_PLUS\b", r"curses.ACS_PLUS", "curses"),
    (r"\bACS_S1\b", r"curses.ACS_S1", "curses"),
    (r"\bACS_S9\b", r"curses.ACS_S9", "curses"),
    (r"\bACS_DIAMOND\b", r"curses.ACS_DIAMOND", "curses"),
    (r"\bACS_CKBOARD\b", r"curses.ACS_CKBOARD", "curses"),
    (r"\bACS_DEGREE\b", r"curses.ACS_DEGREE", "curses"),
    (r"\bACS_PLMINUS\b", r"curses.ACS_PLMINUS", "curses"),
    (r"\bACS_BULLET\b", r"curses.ACS_BULLET", "curses"),
    (r"\bACS_LARROW\b", r"curses.ACS_LARROW", "curses"),
    (r"\bACS_RARROW\b", r"curses.ACS_RARROW", "curses"),
    (r"\bACS_DARROW\b", r"curses.ACS_DARROW", "curses"),
    (r"\bACS_UARROW\b", r"curses.ACS_UARROW", "curses"),
    (r"\bACS_BOARD\b", r"curses.ACS_BOARD", "curses"),
    (r"\bACS_LANTERN\b", r"curses.ACS_LANTERN", "curses"),
    (r"\bACS_BLOCK\b", r"curses.ACS_BLOCK", "curses"),
    (r"\bBUTTON(\d)_PRESSED\b", r"BUTTON\1_PRESSED", "curses"),
    (r"\bBUTTON(\d)_RELEASED\b", r"BUTTON\1_RELEASED", "curses"),
    (r"\bBUTTON(\d)_CLICKED\b", r"BUTTON\1_CLICKED", "curses"),
    (r"\bBUTTON(\d)_DOUBLE_CLICKED\b", r"BUTTON\1_DOUBLE_CLICKED", "curses"),
    (r"\bBUTTON(\d)_TRIPLE_CLICKED\b", r"BUTTON\1_TRIPLE_CLICKED", "curses"),
    (r"\bBUTTON_SHIFT\b", r"BUTTON_SHIFT", "curses"),
    (r"\bBUTTON_CTRL\b", r"BUTTON_CTRL", "curses"),
    (r"\bBUTTON_ALT\b", r"BUTTON_ALT", "curses"),
    (r"\bALL_MOUSE_EVENTS\b", r"ALL_MOUSE_EVENTS", "curses"),
    (r"\bREPORT_MOUSE_POSITION\b", r"REPORT_MOUSE_POSITION", "curses"),
    # Python curses.ascii library
    (r"\bisalnum\(", r"curses.ascii.isalnum(", "curses.ascii"),
    (r"\bisalpha\(", r"curses.ascii.isalpha(", "curses.ascii"),
    (r"\bisascii\(", r"curses.ascii.isascii(", "curses.ascii"),
    (r"\bisblank\(", r"curses.ascii.isblank(", "curses.ascii"),
    (r"\biscntrl\(", r"curses.ascii.iscntrl(", "curses.ascii"),
    (r"\bisdigit\(", r"curses.ascii.isdigit(", "curses.ascii"),
    (r"\bisgraph\(", r"curses.ascii.isgraph(", "curses.ascii"),
    (r"\bislower\(", r"curses.ascii.islower(", "curses.ascii"),
    (r"\bisprint\(", r"curses.ascii.isprint(", "curses.ascii"),
    (r"\bispunct\(", r"curses.ascii.ispunct(", "curses.ascii"),
    (r"\bisspace\(", r"curses.ascii.isspace(", "curses.ascii"),
    (r"\bisupper\(", r"curses.ascii.isupper(", "curses.ascii"),
    (r"\bisxdigit\(", r"curses.ascii.isxdigit(", "curses.ascii"),
    (r"\bisctrl\(", r"curses.ascii.isctrl(", "curses.ascii"),
    (r"\bismeta\(", r"curses.ascii.ismeta(", "curses.ascii"),
    # Python errno library
    (r"\bEPERM\b", r"errno.EPERM", "errno"),
    (r"\bENOENT\b", r"errno.ENOENT", "errno"),
    (r"\bESRCH\b", r"errno.ESRCH", "errno"),
    (r"\bEINTR\b", r"errno.EINTR", "errno"),
    (r"\bEIO\b", r"errno.EIO", "errno"),
    (r"\bENXIO\b", r"errno.ENXIO", "errno"),
    (r"\bE2BIG\b", r"errno.E2BIG", "errno"),
    (r"\bENOEXEC\b", r"errno.ENOEXEC", "errno"),
    (r"\bEBADF\b", r"errno.EBADF", "errno"),
    (r"\bECHILD\b", r"errno.ECHILD", "errno"),
    (r"\bEAGAIN\b", r"errno.EAGAIN", "errno"),
    (r"\bENOMEM\b", r"errno.ENOMEM", "errno"),
    (r"\bEACCES\b", r"errno.EACCES", "errno"),
    (r"\bEFAULT\b", r"errno.EFAULT", "errno"),
    (r"\bENOTBLK\b", r"errno.ENOTBLK", "errno"),
    (r"\bEBUSY\b", r"errno.EBUSY", "errno"),
    (r"\bEEXIST\b", r"errno.EEXIST", "errno"),
    (r"\bEXDEV\b", r"errno.EXDEV", "errno"),
    (r"\bENODEV\b", r"errno.ENODEV", "errno"),
    (r"\bENOTDIR\b", r"errno.ENOTDIR", "errno"),
    (r"\bEISDIR\b", r"errno.EISDIR", "errno"),
    (r"\bEINVAL\b", r"errno.EINVAL", "errno"),
    (r"\bENFILE\b", r"errno.ENFILE", "errno"),
    (r"\bEMFILE\b", r"errno.EMFILE", "errno"),
    (r"\bENOTTY\b", r"errno.ENOTTY", "errno"),
    (r"\bETXTBSY\b", r"errno.ETXTBSY", "errno"),
    (r"\bEFBIG\b", r"errno.EFBIG", "errno"),
    (r"\bENOSPC\b", r"errno.ENOSPC", "errno"),
    (r"\bESPIPE\b", r"errno.ESPIPE", "errno"),
    (r"\bEROFS\b", r"errno.EROFS", "errno"),
    (r"\bEMLINK\b", r"errno.EMLINK", "errno"),
    (r"\bEPIPE\b", r"errno.EPIPE", "errno"),
    (r"\bEDOM\b", r"errno.EDOM", "errno"),
    (r"\bERANGE\b", r"errno.ERANGE", "errno"),
    (r"\bEDEADLK\b", r"errno.EDEADLK", "errno"),
    (r"\bENAMETOOLONG\b", r"errno.ENAMETOOLONG", "errno"),
    (r"\bENOLCK\b", r"errno.ENOLCK", "errno"),
    (r"\bENOSYS\b", r"errno.ENOSYS", "errno"),
    (r"\bENOTEMPTY\b", r"errno.ENOTEMPTY", "errno"),
    (r"\bELOOP\b", r"errno.ELOOP", "errno"),
    (r"\bEWOULDBLOCK\b", r"errno.EWOULDBLOCK", "errno"),
    (r"\bENOMSG\b", r"errno.ENOMSG", "errno"),
    (r"\bEIDRM\b", r"errno.EIDRM", "errno"),
    (r"\bECHRNG\b", r"errno.ECHRNG", "errno"),
    (r"\bEL2NSYNC\b", r"errno.EL2NSYNC", "errno"),
    (r"\bEL3HLT\b", r"errno.EL3HLT", "errno"),
    (r"\bEL3RST\b", r"errno.EL3RST", "errno"),
    (r"\bELNRNG\b", r"errno.ELNRNG", "errno"),
    (r"\bEUNATCH\b", r"errno.EUNATCH", "errno"),
    (r"\bENOCSI\b", r"errno.ENOCSI", "errno"),
    (r"\bEL2HLT\b", r"errno.EL2HLT", "errno"),
    (r"\bEBADE\b", r"errno.EBADE", "errno"),
    (r"\bEBADR\b", r"errno.EBADR", "errno"),
    (r"\bEXFULL\b", r"errno.EXFULL", "errno"),
    (r"\bENOANO\b", r"errno.ENOANO", "errno"),
    (r"\bEBADRQC\b", r"errno.EBADRQC", "errno"),
    (r"\bEBADSLT\b", r"errno.EBADSLT", "errno"),
    (r"\bEDEADLOCK\b", r"errno.EDEADLOCK", "errno"),
    (r"\bEBFONT\b", r"errno.EBFONT", "errno"),
    (r"\bENOSTR\b", r"errno.ENOSTR", "errno"),
    (r"\bENODATA\b", r"errno.ENODATA", "errno"),
    (r"\bETIME\b", r"errno.ETIME", "errno"),
    (r"\bENOSR\b", r"errno.ENOSR", "errno"),
    (r"\bENONET\b", r"errno.ENONET", "errno"),
    (r"\bENOPKG\b", r"errno.ENOPKG", "errno"),
    (r"\bEREMOTE\b", r"errno.EREMOTE", "errno"),
    (r"\bENOLINK\b", r"errno.ENOLINK", "errno"),
    (r"\bEADV\b", r"errno.EADV", "errno"),
    (r"\bESRMNT\b", r"errno.ESRMNT", "errno"),
    (r"\bECOMM\b", r"errno.ECOMM", "errno"),
    (r"\bEPROTO\b", r"errno.EPROTO", "errno"),
    (r"\bEMULTIHOP\b", r"errno.EMULTIHOP", "errno"),
    (r"\bEDOTDOT\b", r"errno.EDOTDOT", "errno"),
    (r"\bEBADMSG\b", r"errno.EBADMSG", "errno"),
    (r"\bEOVERFLOW\b", r"errno.EOVERFLOW", "errno"),
    (r"\bENOTUNIQ\b", r"errno.ENOTUNIQ", "errno"),
    (r"\bEBADFD\b", r"errno.EBADFD", "errno"),
    (r"\bEREMCHG\b", r"errno.EREMCHG", "errno"),
    (r"\bELIBACC\b", r"errno.ELIBACC", "errno"),
    (r"\bELIBBAD\b", r"errno.ELIBBAD", "errno"),
    (r"\bELIBSCN\b", r"errno.ELIBSCN", "errno"),
    (r"\bELIBMAX\b", r"errno.ELIBMAX", "errno"),
    (r"\bELIBEXEC\b", r"errno.ELIBEXEC", "errno"),
    (r"\bEILSEQ\b", r"errno.EILSEQ", "errno"),
    (r"\bERESTART\b", r"errno.ERESTART", "errno"),
    (r"\bESTRPIPE\b", r"errno.ESTRPIPE", "errno"),
    (r"\bEUSERS\b", r"errno.EUSERS", "errno"),
    (r"\bENOTSOCK\b", r"errno.ENOTSOCK", "errno"),
    (r"\bEDESTADDRREQ\b", r"errno.EDESTADDRREQ", "errno"),
    (r"\bEMSGSIZE\b", r"errno.EMSGSIZE", "errno"),
    (r"\bEPROTOTYPE\b", r"errno.EPROTOTYPE", "errno"),
    (r"\bENOPROTOOPT\b", r"errno.ENOPROTOOPT", "errno"),
    (r"\bEPROTONOSUPPORT\b", r"errno.EPROTONOSUPPORT", "errno"),
    (r"\bESOCKTNOSUPPORT\b", r"errno.ESOCKTNOSUPPORT", "errno"),
    (r"\bEOPNOTSUPP\b", r"errno.EOPNOTSUPP", "errno"),
    (r"\bEPFNOSUPPORT\b", r"errno.EPFNOSUPPORT", "errno"),
    (r"\bEAFNOSUPPORT\b", r"errno.EAFNOSUPPORT", "errno"),
    (r"\bEADDRINUSE\b", r"errno.EADDRINUSE", "errno"),
    (r"\bEADDRNOTAVAIL\b", r"errno.EADDRNOTAVAIL", "errno"),
    (r"\bENETDOWN\b", r"errno.ENETDOWN", "errno"),
    (r"\bENETUNREACH\b", r"errno.ENETUNREACH", "errno"),
    (r"\bENETRESET\b", r"errno.ENETRESET", "errno"),
    (r"\bECONNABORTED\b", r"errno.ECONNABORTED", "errno"),
    (r"\bECONNRESET\b", r"errno.ECONNRESET", "errno"),
    (r"\bENOBUFS\b", r"errno.ENOBUFS", "errno"),
    (r"\bEISCONN\b", r"errno.EISCONN", "errno"),
    (r"\bENOTCONN\b", r"errno.ENOTCONN", "errno"),
    (r"\bESHUTDOWN\b", r"errno.ESHUTDOWN", "errno"),
    (r"\bETOOMANYREFS\b", r"errno.ETOOMANYREFS", "errno"),
    (r"\bETIMEDOUT\b", r"errno.ETIMEDOUT", "errno"),
    (r"\bECONNREFUSED\b", r"errno.ECONNREFUSED", "errno"),
    (r"\bEHOSTDOWN\b", r"errno.EHOSTDOWN", "errno"),
    (r"\bEHOSTUNREACH\b", r"errno.EHOSTUNREACH", "errno"),
    (r"\bEALREADY\b", r"errno.EALREADY", "errno"),
    (r"\bEINPROGRESS\b", r"errno.EINPROGRESS", "errno"),
    (r"\bESTALE\b", r"errno.ESTALE", "errno"),
    (r"\bEUCLEAN\b", r"errno.EUCLEAN", "errno"),
    (r"\bENOTNAM\b", r"errno.ENOTNAM", "errno"),
    (r"\bENAVAIL\b", r"errno.ENAVAIL", "errno"),
    (r"\bEISNAM\b", r"errno.EISNAM", "errno"),
    (r"\bEREMOTEIO\b", r"errno.EREMOTEIO", "errno"),
    (r"\bEDQUOT\b", r"errno.EDQUOT", "errno"),
    # Python fcntl library
    (r"\bfcntl\(", r"fcntl.fcntl(", "fcntl"),
    (r"\bflock\(", r"fcntl.lockf(", "fcntl"),
    (r"\blockf\(", r"fcntl.lockf(", "fcntl"),
    (r"\bLOCK_UN\b", r"fcntl.LOCK_UN", "fcntl"),
    (r"\bLOCK_EX\b", r"fcntl.LOCK_EX", "fcntl"),
    (r"\bLOCK_SH\b", r"fcntl.LOCK_SH", "fcntl"),
    (r"\bLOCK_NB\b", r"fcntl.LOCK_NB", "fcntl"),
    # Python getpass library
    (r"\bgetpass\(", r"getpass.getpass(", "getpass"),
    # Python glob library
    (r"\bglob\(", r"glob.glob(", "glob"),   # Calling conventions differ
    # Python grp library
    (r"\bgetgrgid\(", r"grp.getgrgid(", "grp"),
    (r"\bgetgrnam\(", r"grp.getgrnam(", "grp"),
    # Python math library
    (r"\bacos\(", r"math.acos(", "math"),
    (r"\basin\(", r"math.asin(", "math"),
    (r"\batan\(", r"math.atan(", "math"),
    (r"\batan2\(", r"math.atan2(", "math"),
    (r"\bceil\(", r"math.ceil(", "math"),
    (r"\bcos\(", r"math.cos(", "math"),
    (r"\bcosh\(", r"math.cosh(", "math"),
    (r"\bexp\(", r"math.exp(", "math"),
    (r"\bfabs\(", r"math.fabs(", "math"),
    (r"\bfloor\(", r"math.floor(", "math"),
    (r"\bfmod\(", r"math.fmod(", "math"),
    (r"\bfrexp\(", r"math.frexp(", "math"), # Calling conventions differ
    (r"\bldexp\(", r"math.ldexp(", "math"),
    (r"\blog10\(", r"math.log10(", "math"),
    (r"\blog\(", r"math.log(", "math"),
    (r"\bmodf\(", r"math.modf(", "math"),   # Calling conventions differ
    (r"\bpow\(", r"math.pow(", "math"),
    (r"\bsinh\(", r"math.sinh(", "math"),
    (r"\bsin\(", r"math.sin(", "math"),
    (r"\bsqrt\(", r"math.sqrt(", "math"),
    (r"\btan\(", r"math.tan(", "math"),
    (r"\btanh\(", r"math.tanh(", "math"),
    # Python os library
    (r"\babort\(", r"os.abort(", "os"),
    (r"\baccess\(", r"os.access(", "os"),
    (r"\bchdir\(", r"os.chdir(", "os"),
    (r"\bclose\(", r"os.close(", "os"),
    (r"\benviron\(", r"os.environ(", "os"),
    (r"\bfchdir\(", r"os.fchdir(", "os"),
    (r"\bchroot\(", r"os.chroot(", "os"),
    (r"\bchmod\(", r"os.chmod(", "os"),
    (r"\bchown\(", r"os.chown(", "os"),
    (r"\bctermid\(", r"os.ctermid(", "os"),
    (r"\bdup\(", r"os.dup(", "os"),
    (r"\bdup2\(", r"os.dup2(", "os"),
    (r"\bexecl\(", r"os.execl(", "os"),
    (r"\bexecle\(", r"os.execle(", "os"),
    (r"\bexeclp\(", r"os.execlp(", "os"),
    (r"\bexeclpe\(", r"os.execlpe(", "os"),
    (r"\bexecv\(", r"os.execv(", "os"),
    (r"\bexecve\(", r"os.execve(", "os"),
    (r"\bexecvp\(", r"os.execvp(", "os"),
    (r"\bexecvpe\(", r"os.execvpe(", "os"),
    (r"\b_exit\(", r"os._exit(", "os"),
    (r"\bexit\(", r"os.exit(", "os"),
    (r"\bfdopen\(", r"os.fdopen(", "os"),
    (r"\bfork\(", r"os.fork(", "os"),
    (r"\bfsync\(", r"os.fsync(", "os"),
    (r"\bftruncate\(", r"os.ftruncate(", "os"),
    (r"\bgetcwd\(", r"os.getcwd(", "os"),
    (r"\bgetegid\(", r"os.getegid(", "os"),
    (r"\bgeteuid\(", r"os.geteuid(", "os"),
    (r"\bgetenv\(", r"os.getenv(", "os"),
    (r"\bgetgid\(", r"os.getgid(", "os"),
    (r"\bgetgroups\(", r"os.getgroups(", "os"),
    (r"\bgetlogin\(", r"os.getlogin(", "os"),
    (r"\bgetpgid\(", r"os.getpgid(", "os"),
    (r"\bgetpgrp\(", r"os.getpgrp(", "os"),
    (r"\bgetpid\(", r"os.getpid(", "os"),
    (r"\bgetppid\(", r"os.getppid(", "os"),
    (r"\bgetuid\(", r"os.getuid(", "os"),
    (r"\bkill\(", r"os.kill(", "os"),
    (r"\bkillpg\(", r"os.killpg(", "os"),
    (r"\bisatty\(", r"os.isatty(", "os"),
    (r"\blseek\(", r"os.lseek(", "os"),
    (r"\blchown\(", r"os.lchown(", "os"),
    (r"\bgetcwd\(", r"os.getcwd(", "os"),
    (r"\blstat\(", r"os.lstat(", "os"),
    (r"\bmkfifo\(", r"os.mkfifo(", "os"),
    (r"\bmknod\(", r"os.mknod(", "os"),
    (r"\bmkdir\(", r"os.mkdir(", "os"),
    (r"\bnice\(", r"os.nice(", "os"),
    (r"\bopen\(", r"os.open(", "os"),
    (r"\bpathconf\(", r"os.pathconf(", "os"),
    (r"\bpipe\(", r"os.pipe(", "os"),
    (r"\bplock\(", r"os.plock(", "os"),
    (r"\bputenv\(", r"os.putenv(", "os"),
    (r"\bread\(", r"os.read(", "os"),
    (r"\brmdir\(", r"os.rmdir(", "os"),
    (r"\bsetegid\(", r"os.setegid(", "os"),
    (r"\bseteuid\(", r"os.seteuid(", "os"),
    (r"\bsetgid\(", r"os.setgid(", "os"),
    (r"\bsetgroups\(", r"os.setgroups(", "os"),
    (r"\bsetpgrp\(", r"os.setpgrp(", "os"),
    (r"\bsetpgid\(", r"os.setpgid(", "os"),
    (r"\bsetreuid\(", r"os.setreuid(", "os"),
    (r"\bsetregid\(", r"os.setregid(", "os"),
    (r"\bsetsid\(", r"os.setsid(", "os"),
    (r"\bsetuid\(", r"os.setuid(", "os"),
    (r"\bstrerror\(", r"os.strerror(", "os"),
    (r"\bumask\(", r"os.umask(", "os"),
    (r"\bsymlink\(", r"os.symlink(", "os"),
    (r"\bsystem\(", r"os.system(", "os"),
    (r"\btcgetpgrp\(", r"os.tcgetpgrp(", "os"),
    (r"\btcsetpgrp\(", r"os.tcsetpgrp(", "os"),
    (r"\btmpfile\(", r"os.tmpfile(", "os"),
    (r"\bttyname\(", r"os.ttyname(", "os"),
    (r"\bunlink\(", r"os.unlink(", "os"),
    (r"\bwrite\(", r"os.write(", "os"),
    (r"\bwait\(", r"os.wait(", "os"),
    (r"\bwaitpid\(", r"os.waitpid(", "os"),
    (r"\bWNOHANG\b", r"os.WNOHANG", "os"),
    (r"\bWCONTINUED\b", r"os.WCONTINUED", "os"),
    (r"\bWUNTRACED\b", r"os.WUNTRACED", "os"),
    (r"\bWCOREDUMP\b", r"os.WCOREDUMP", "os"),
    (r"\bWIFCONTINUED\b", r"os.WIFCONTINUED", "os"),
    (r"\bWIFSTOPPED\b", r"os.WIFSTOPPED", "os"),
    (r"\bWIFSIGNALED\b", r"os.WIFSIGNALED", "os"),
    (r"\bWIFEXITED\b", r"os.WIFEXITED", "os"),
    (r"\bWEXITSTATUS\b", r"os.WEXITSTATUS", "os"),
    (r"\bWSTOPSIG\b", r"os.WSTOPSIG", "os"),
    (r"\bWTERMSIG\b", r"os.WTERMSIG", "os"),
    (r"\bO_RDONLY\b", r"os.O_RDONLY", "os"),
    (r"\bO_WRONLY\b", r"os.O_WRONLY", "os"),
    (r"\bO_RDWR\b", r"os.O_RDWR", "os"),
    (r"\bO_NDELAY\b", r"os.O_NDELAY", "os"),
    (r"\bO_NONBLOCK\b", r"os.O_NONBLOCK", "os"),
    (r"\bO_APPEND\b", r"os.O_APPEND", "os"),
    (r"\bO_DSYNC\b", r"os.O_DSYNC", "os"),
    (r"\bO_RSYNC\b", r"os.O_RSYNC", "os"),
    (r"\bO_SYNC\b", r"os.O_SYNC", "os"),
    (r"\bO_NOCTTY\b", r"os.O_NOCTTY", "os"),
    (r"\bO_CREAT\b", r"os.O_CREAT", "os"),
    (r"\bO_EXCL\b", r"os.O_EXCL", "os"),
    (r"\bO_TRUNC\b", r"os.O_TRUNC", "os"),
    (r"\bF_OK\b", r"os.F_OK", "os"),
    (r"\bR_OK\b", r"os.R_OK", "os"),
    (r"\bW_OK\b", r"os.W_OK", "os"),
    (r"\bX_OK\b", r"os.X_OK", "os"),
    (r"\bS_ISUID\b", r"os.S_ISUID", "os"),
    (r"\bS+ISGID\b", r"os.S+ISGID", "os"),
    (r"\bS_ENFMT\b", r"os.S_ENFMT", "os"),
    (r"\bS_ISVTX\b", r"os.S_ISVTX", "os"),
    (r"\bS_IREAD\b", r"os.S_IREAD", "os"),
    (r"\bS_IWRITE\b", r"os.S_IWRITE", "os"),
    (r"\bS_IEXEC\b", r"os.S_IEXEC", "os"),
    (r"\bS_IRWXU\b", r"os.S_IRWXU", "os"),
    (r"\bS_IRUSR\b", r"os.S_IRUSR", "os"),
    (r"\bS_IXUSR\b", r"os.S_IXUSR", "os"),
    (r"\bS_IRWXG\b", r"os.S_IRWXG", "os"),
    (r"\bS_IRGRP\b", r"os.S_IRGRP", "os"),
    (r"\bS_IWGRP\b", r"os.S_IWGRP", "os"),
    (r"\bS_IXGRP\b", r"os.S_IXGRP", "os"),
    (r"\bS_IRWXO\b", r"os.S_IRWXO", "os"),
    (r"\bS_IROTH\b", r"os.S_IROTH", "os"),
    (r"\bS_IWOTH\b", r"os.S_IWOTH", "os"),
    (r"\bS_IXOTH\b", r"os.S_IXOTH", "os"),
    # Python os.path library
    (r"\bbasename\(", r"os.path.basename(", "os.path"),
    (r"\bdirname\(", r"os.path.dirname(", "os.path"),
    # Python pwd library
    (r"\bgetpwuid\(", r"pwd.getpwuid(", "pwd"),
    (r"\bgetpwnam\(", r"pwd.getpwnam(", "pwd"),
    # Python random library -- alas, C rand() doesn't map cleanly
    (r"\bsrand48\(", r"random.seed(", "random"),
    (r"\bsrand\(", r"random.seed(", "random"),
    # Python string library
    (r"\btoupper\(%(farg)s\)", r"\1.upper(", None),
    (r"\btolower\(%(farg)s\)", r"\1.lower(", None),
    # Python sys library
    (r"\bargv\(", r"sys.argv(", "sys"),
    (r"\bstdin\(", r"sys.stdin(", "sys"),
    (r"\bstdout\(", r"sys.stdout(", "sys"),
    (r"\bstderr\(", r"sys.stderr(", "sys"),
    # Python termios library
    (r"\btcgetattr\(", r"termios.tcgetattr(", "termios"),   # Calling conventions differ
    (r"\btcsetattr\(", r"termios.tcsetattr(", "termios"),   # Calling conventions differ
    (r"\btcsendbreak\(", r"termios.tcsendbreak(", "termios"),
    (r"\btcflush\(", r"termios.tcflush(", "termios"),
    (r"\btcdrain\(", r"termios.tcdrain(", "termios"),
    (r"\btcflow\(", r"termios.tcflow(", "termios"),
    (r"\bVMIN\b", r"termios.VMIN", "termios"),
    (r"\bVMAX\b", r"termios.VMAX", "termios"),
    (r"\bTCSANOW\b", r"termios.TCSANOW", "termios"),
    (r"\bTCSADRAIN\b", r"termios.TCSADRAIN", "termios"),
    (r"\bTCSAFLUSH\b", r"termios.TCSAFLUSH", "termios"),
    (r"\bTCIFLUSH\b", r"termios.TCIFLUSH", "termios"),
    (r"\bTCOFLUSH\b", r"termios.TCOFLUSH", "termios"),
    (r"\bTCOOFF\b", r"termios.TCOOFF", "termios"),
    (r"\bTCOON\b", r"termios.TCOON", "termios"),
)

falsefriends = (
    r"frexp", r"glob", r"ioctl", r"modf", r"tcgetattr", r"tcsetattr",
    r"ungetmouse",
    )

# These have to be applied to the entire file without breaking it into regions
file_transformations = (
    # Simple initializers to tuples
    (r"(?:static)?\s+(?:%(type)s|%(class)s)\s+(%(id)s)\[[a-zA-Z0-9._]*]\s*=\s*{([^}]+)}",
     r"\1 = (\2)"),
    (r"enum\s+(%(id)s\s*){\s*",  r"enum \1{\n"),
    (r"enum\s+{\s*",  r"enum {\n"),
    (r"%(ind)s#\s*\$ctopy.*", r""), # Make hints go away
    (r"(?:int )?main\(int\s+argc,\s+char\s+\*argv\)\s*{",
     "if __name__ == '__main__':"),
    )

# These need to be applied repeatedly within regions.
# They rely on semicolons as statatement end markers.
repeat_transformations = (
    (
    # Group 1: What we're doing here is stripping out prefix, suffix,
    # and wrapper parts of declarations in order to reduce everything
    # to base type followed by whitespace followed by id.  This is
    # significant for simplifying both function formal parameter lists
    # and variable declaration lines.  We'll get rid of the remaining
    # type stuff in a later pass.
    (r"(%(type)s|%(class)s)\s*\*", r"\1 "), # Pointer type decls
    (r"(%(type)s|%(class)s)(.*), \*", r"\1\2, "),   # Pointer type decls
    (r"(%(type)s|%(class)s)\s*\((%(id)s)\)\(\)", r"\1 \2"), # Function pointer wrappers
    (r"(%(type)s|%(class)s)\s*(%(id)s)\[\]", r"\1 \2"), # Array declarators
    ),
    (
    # Group 2: Translate function headers.  This needs to happen after
    # reduction to base types (just above) but before scalar types
    # have been removed entirely.
    (r"\n(?:static\s+)?(?:%(type)s|%(class)s) +(.*\)) *\n", r"\ndef \1:\n"),
    ),
    (
    # Group 3: What we're doing here is trying to get rid of variable
    # declarations that don't have initializer parts.
    # Scalar-vars just after the type and before a comma go away.
    (r"(\n[ \t]*(?:%(type)s))(\s*%(id)s),", r"\1 "),
    # Scalar-vars just after type and before a semi go away, but semi stays.
    (r"(\n[ \t]*(?:%(type)s))(\s*%(id)s);", r"\1;"),
    # Class-vars after class names and before comma or semi get an initializer.
    (r"(\n[ \t]*)(%(class)s)(\s*%(id)s)([;,])", r"\1\2\3 = \2()\4"),
    # Scalar-vars between a comma and a trailing semicolon go away.
    (r"(\n[ \t]*)((?:%(type)s).*)(,\s*%(id)s\s*);", r"\1\2;"),
    # Class-Vars between comma and semicolon get a following initializer 
    (r"(\n[ \t]*)(%(class)s)(.*,\s)*(%(id)s)(\s*;)", r"\1\2\3\4 = \2()\5"),
    # Scalar-vars between commas in a declaration line go away.
    (r"(\n[ \t]*(?:%(type)s)\s+.*)(,\s*%(id)s)(,.*);", r"\1\3;"),
    # Bare class-vars between commas get an initializer
    (r"(\n[ \t]*)(%(class)s)(\s+.*,)(\s*%(id)s),(.*);",r"\1\2\3\4 = \2(),\5;"),
    # Any declaration line not containing an initializer goes away.
    (r"\n[ \t]*(?:%(type)s|%(class)s)[^=;]*;", r""),
    ),
    (
    # Group 4: At this point all declarations left have initializers.
    # Replace commas in declaration lines with semis, otherwise Python will
    # barf later because it thinks that, e.g., a=4, b=5  is an attempt to
    # assign a constant to a tuple.
    # FIXME: This will fail messily on GCC structure intializers.
    (r"(\n[ \t]*(?:%(type)s|%(class)s).*),(.*);", r"\1;\2"),
    ),
    (
    # Group 5: Now rip out all remaining base type information.
    # This will strip remaining type declarators out of formal parameter lists.
    # It will also remove types from the beginning of declaration lines.
    # Won't nuke casts because it looks for at least one following whitespace.
    (r"(?:%(type)s|%(class)s)[\s;]\s*", r""),
    ),
)

# These get applied once within regions, before type info has been stripped
pre_transformations = (
    # We used to do function header translation here.   We leave
   # this in place because we'll probably need to do things here again.
    )

# These get applied once within regions, after type info has been stripped
post_transformations = (
    # some consequences of having translated function headers
    (r"\(void\):\n", r"():\n"),
    (r"def(.*):\n\Z", r"def\1:\n    "), # indent comment on line after def
    # externs can just disappear -- this may discard a following comment
    (r"extern[^;]+;.*\n", r""),
    # macros
    (r"#define\s+(%(id)s)\s+(.*)", r"\1\t= \2"),
    (r"#define\s+(%(id)s)\(([^)]*)\)\s+(.*\))", r"def \1(\2):\treturn \3"),
    (r"#define\s+(%(id)s)\(([^)]*)\)\s+([^(].*)", r"def \1(\2):\t\3"),
    # control structure
    (r"\bif *\((.*)\)(\s*{)?", r"if \1:"),
    (r"\bdo\s*{", r"while True:"),
    (r"}\s*while\s*(\(.*\));", r"    if not \1: break   # DO-WHILE TERMINATOR -- INDENTATION CAN BE WRONG"), 
    (r"\bwhile *\((.*)\)(\s*{)?", r"while \1:"), 
    (r"\bwhile 1:", r"while True:"),
    (r"\bfor \(;;\)(\s*{)?", r"while True:"),
    (r"\bfor \((%(id)s) *= *0; *\1 *<= *([^;]+); *\1\+\+\)(\s*{)?",
                        r"for \1 in range(\2+1):"),
    (r"\bfor \((%(id)s) *= *([^;]+); *\1 *<= *([^;]+); *\1\+\+\)(\s*{)?",
                        r"for \1 in range(\2, \3+1):"),
    (r"\bfor \((%(id)s) *= *0; *\1 *< *([^;]+); *\1\+\+\)\s*{",
                        r"for \1 in range(\2):"),
    (r"\bfor \((%(id)s) *= *([^;]+); *\1 *< *([^;]+); *\1\+\+\)(\s*{)?",
                        r"for \1 in range(\2, \3):"),
    (r"else if", r"elif"),
    (r"(?:} )?else\s*{", r"else"),
    (r"(?<!#)else", r"else:"),
    (r"switch *\((.*)\)(\s*{)?", r"switch \1:"),# Not Python, but less ugly
    # constants
    (r"\btrue\b", r"True"), # C99
    (r"\bfalse\b", r"False"),   # C99
    (r"\bTRUE\b", r"True"), # pre-C99
    (r"\bFALSE\b", r"False"),   # pre-C99
    # expression operations
    (r" *\&\& *", r" and "),
    (r" *\|\| *", r" or "),
    (r"-\>", r"."),
    (r"!(?!=) *", r"not "),
    (r"(and|or) *\n", r"\1 \\\n"),
    # most common uses of address operator
    (r"return *&", r"return "),
    (r"= *&", r"= "),
    # increment and decrement statements
    (r"(%(id)s)\+\+([;\n])", r"\1 += 1\2"),
    (r"(%(id)s)--([;\n])", r"\1 -= 1\2"),
    (r"\+\+(%(id)s)([;\n])", r"\1 += 1\2"),
    (r"--(%(id)s)([;\n])", r"\1 -= 1\2"),
    # no-op voids
    (r"\n[ \t]*\(void\)", r"\n"),  
    # C functions that turn into Python builtins
    (r"\batoi\(", r"int("),
    (r"\batof\(", r"float("),
    (r"\batol\(", r"long("),
    (r"\bfopen\(", r"open("),
    (r"\bputchar\(", r"stdout.write("),
    (r"\bgetchar\(\)", r"stdout.read(1)"),
    (r"\bstrlen\(", r"len("),
    (r"\bstrcmp\((%(exp)s),\s*(%(exp)s)\)\s*==\s*0", r"\1 == \2"),
    (r"\bstrcmp\((%(exp)s),\s*(%(exp)s)\)\s*!=\s*0", r"\1 != \2"),
    (r"\bstrcpy\((%(exp)s),\s*(%(exp)s)\)", r"\1 = \2"),
    # Python time library
    (r"\btime\(NULL\)", r"time.time()"),
    # well-known includes
    (r"#include \<string.h\>\n", r""),
    (r"#include \<stdlib.h\>\n", r""),
    (r"#include \<stdbool.h\>\n", r""),
    (r"#include \<stdio.h\>\n", r"import sys\n"),
    (r"#include \<math.h\>\n", r"import math\n"),
    (r"#include \<time.h\>\n", r"import time\n"),
    (r"#include \<regex.h\>\n", r"import re\n"),
    (r"#include \<curses.h\>\n", r"import curses\n"),
    (r"#include \<termios.h\>\n", r"import termios\n"),
)

final_transformations = (
    # block delimiters -- do these as late as possible, they're useful
    (r";(%(eol)s)", r"\1"),
    (r"\n[ \t]*}%(eol)s", r""),
    (r"(?<!=\n)\n{\n", r"\n"),  # Start-of-line brace that's not an initializer
    (r"%% \(,(%(ind)s)", r"%\1("),
    (r"not \(not \((.+)\)\)", r"\1"),
    )

def single_apply(transforms, text):
    "Apply specified set of transformations once."
    for (fro, to) in transforms:
        oldtext = text
        # Prepending \n then stripping it means that \n can reliably
        # be used to recognize start of line.
        text = re.sub(fro % shorthands, to, "\n" + oldtext)[1:]
        if debug >= 2 and text != oldtext:
            print ("%s transforms '%s' to '%s'" % ((fro, to), 'oldtext', 'text'))
    return text

def repeat_apply(transforms, text):
    "Repeatedly apply specified transformations to text until it's stable."
    while True:
        transformed = single_apply(transforms, text)
        if transformed != text:
            text = transformed
        else:
            break
    return text

def ctopy(input):
    "Transform C to Python."
    if debug >= 2:
        print ("Gathering hints")
    hints = re.finditer(r"\$ctopy (.*)", input)
    for hint in hints:
        process_hint(hint.group(1))
    if debug >= 2:
        print ("Processing inline enums")
    global stringify
    enums = re.finditer(r"enum[ \t]*{(.*)} (%(id)s)" % shorthands, input)
    for instance in enums:
        stringify += instance.group(1).replace(" ", "").split(",")
        input = input[:instance.start(0)] + input[instance.start(2):]
    if debug:
        print ("Pre-transformations begin")
    input = repeat_apply(file_transformations, input)
    if debug >= 2:
        print ("After pre-transformations: %s" % 'code')
    if debug:
        print ("Region analysis begins")
    boundaries = [0]
    state = "text"
    for i in range(len(input)):
        if state == "text":
            if input[i] == '"' and (i == 0 or input[i-1] != '\\'):
                if debug >= 2:
                    print ("String literal starts at %d" % i)
                boundaries.append(i)
                state = "stringliteral"
            elif input[i:i+2] == "/*":
                if debug >= 2:
                    print ("Closed comment starts at %d" % (i-1))
                boundaries.append(i)
                state = "closedcomment"
            elif input[i:i+2] == "//":
                if debug >= 2:
                    print("Open comment starts at %d" % i)
                boundaries.append(i)
                state = "opencomment"
            elif input[i:].startswith("typedef enum {") or input[i:].startswith("enum {"):
                if debug >= 2:
                    print ("enumeration starts at %d" % i)
                if input[i-2:i+1] != 'f e':
                    boundaries.append(i)
                boundaries.append(i + input[i:].find("enum") + 5)
            elif input[i:].startswith("\n}"):
                if debug >= 2:
                    print("start-of-line brace at %d" % i)
                boundaries.append(i)
                boundaries.append(i+2)
        elif state == "stringliteral":
            if input[i] == '"' and (i == 0 or input[i-1] != '\\'):
                if debug >= 2:
                    print("String ends at %d" % i)
                boundaries.append(i+1)
                state = "text"
        elif state == "closedcomment":
            if input[i:i+2] == "*/":
                if debug >= 2:
                    print("closed comment ends at %d" % (i+1))
                boundaries.append(i+2)
                state = "text"                
        elif state == "opencomment":
            if input[i] == "\n":
                if debug >= 2:
                    print("Open comment ends at %d" % (i+1))
                boundaries.append(i+1)
                state = "text"
    boundaries.append(len(input))
    if debug >= 2:
        print("Boundaries:", boundaries)
    regions = []
    for i in range(len(boundaries)-1):
        regions.append(input[boundaries[i]:boundaries[i+1]])
    regions = list(filter(lambda x: x != '', regions))
    if debug:
        print("Regexp transformation begins")
    if debug:
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        print("Regions:")
        pp.pprint(regions)
    if debug >= 2:
        print("Processing printf-like functions")
    for (i, here) in enumerate(regions):
        if regions[i][0] != '"' or not "%" in here:
            continue
        else:
            for func in printflike:
                if re.search(r"\b%s\([^;]*\Z" % func, regions[i]):
                    break
                else:
                    continue    # Didn't find printf-like function
        # Found printf-like function.  Replace first comma in the
        # argument region with " % (".  This copes gracefully with the
        # case where the format string is wrapped in _( ) for
        # initialization.
        regions[i+1] = re.sub(r",\s*", r" % (", regions[i+1], 1)
        j = regions[i+1].find("%") + 2
        parenlevel = 0
        while j < len(regions[i+1]):
            if regions[i+1][j] == "(":
                parenlevel += 1
            if regions[i+1][j] == ")":
                parenlevel -= 1
            if parenlevel == 0:
                regions[i+1] = regions[i+1][:j] + ")" + regions[i+1][j:]
                break
            j += 1
    importlist = []
    try:
        for i in range(len(regions)):
            if regions[i][:2] == "/*":
                if regions[i].count("\n") <= 1:     # winged comment
                    regions[i] = "#" + regions[i][2:-2]
                elif re.search("/\*+\n", regions[i]):   # boxed comment
                    regions[i] = re.sub(r"\n([ \t]*) \* ?", r"\n\1",regions[i])
                    regions[i] = re.sub(r"\n([ \t]*)\*", r"\n\1", regions[i])
                    regions[i] = re.sub(r"^([ \t]*)/\*+\n", r"\1#\n", regions[i])
                    regions[i] = re.sub(r"\n([ \t]*)\**/", r"\n\1", regions[i])
                    regions[i] = re.sub(r"\n([ \t]*)(?!#)", r"\n\1# ", regions[i])
                else:
                    regions[i] = regions[i].replace("/*", "#")
                    regions[i] = regions[i].replace("\n*/", "\n#")
                    regions[i] = regions[i].replace("*/", "")
                    regions[i] = regions[i].replace("\n *", "\n")
                    regions[i] = regions[i].replace("\n", "\n#")
            elif regions[i][:2] == "//":
                regions[i] = "#" + regions[i][2:]
            elif regions[i][0] != '"':
                if debug >= 2:
                    print("Doing pre transformations")
                regions[i] = single_apply(pre_transformations, regions[i])
                if debug >= 2:
                    print("Doing repeated transformations")
                for (j, hack) in enumerate(repeat_transformations):
                    if debug >= 2:
                        print("Repeat transformations group %d" % (j+1))
                    regions[i] = repeat_apply(hack, regions[i])
                if debug:
                    print("Function and method mappings begin")
                for (fro, to, module) in funmappings:
                    if re.search(fro, regions[i]):
                        regions[i] = re.sub(fro, to, regions[i])
                        if module not in importlist and module:
                            importlist.append(module)
                for name in falsefriends:
                    if re.search(r"\b" + name + r"\b\(", regions[i]):
                        sys.stderr.write("warning: %s calling conventions differ between C and Python." % name)
                if debug >= 2:
                    print("Doing post transformations")
                regions[i] = single_apply(post_transformations, regions[i])
                for str in stringify:
                    regions[i] = re.sub(r"\b" + str + r"\b",
                                        '"' + str + '"', regions[i])
    except IndexError:
        sys.stderr.write("ctopy: pathological string literal at %d.\n" % boundaries[i])
        raise SystemExit
    if debug:
        print("Enumeration processing")
    state = "plain"
    for (i, region) in enumerate(regions):
        # first compute a parse state
        if region.startswith("typedef enum"):
            state = "typedef"
        elif region.startswith("enum"):
            state = "enum"
        elif region == "\n}":
            if state in ("typedef", "enum"):
                regions[i] = ''
                state = "plain"
        # now do something useful with it
        if debug >= 3:
            print("Enumeration processing: state = %s, region = %s" % (state, 'regions[i]'))
        if state in ("enum", "typedef"):
            if regions[i] == "enum ":
                m = re.match("(%(id)s) {" % shorthands, regions[i+1])
                if m:
                    shorthands['type'] += "|" + m.group(1)
                    regions[i] = '# From enumerated type \'%s\'\n' % m.group(1)
                    regions[i+1] = regions[i+1][m.end(0)+1:]
                else: 
                    regions[i] = '# From anonymous enumerated type\n'
            elif regions[i] == "typedef enum ":
                m = re.match("\s* (%(id)s)\s*;?" % shorthands, regions[i+3])
                if m:
                    shorthands['type'] += "|" + m.group(1)
                    regions[i] = '# From enumerated type \'%s\'\n' % m.group(1)
                    regions[i+3] = regions[i+3][:m.start(0)] + "\n\n"
                else: 
                    regions[i] = '# From anonymous typedefed enum (?!)\n'
            else:
                regions[i] = re.sub(",\s*", "\n", regions[i])
                val = 0
                txt = regions[i].split("\n")
                for j in range(len(txt)):
                    if txt[j] == '' or txt[j].startswith("{"):
                        pass
                    elif '=' not in txt[j]:
                        txt[j] += " = %d" % val
                        val += 1
                regions[i] = "\n".join(txt)
    if debug:
        print("Final transformations begin")
    regions = map(lambda r: repeat_apply(final_transformations, r),regions)
    text = "".join(regions)
    if importlist:
        importlist = "import " + ", ".join(importlist) + "\n"
        text = importlist + text
    # Emit what we got.  Preserve imports in case this is a .h file 
    return text

def process_hint(line):
    "Process a translation-hints line."
    if line[0] == "#":
        pass
    else:
        global stringify, printflike
        if debug >= 2:
            print("Hint: %s" % 'line')
        lst = line.replace(",", " ").split()
        if lst[0] == "stringify":
            stringify += lst[1:]
        elif lst[0] == "type":
            for tok in lst[1:]:
                shorthands["type"] += r"|\b" + tok + r"\b" 
        elif lst[0] == "class":
            for tok in lst[1:]:
                shorthands["class"] += r"|\b" + tok + r"\b"
        elif lst[0] == "printflike":
            printflike += lst[1:]

if __name__ == "__main__":
    import getopt
    (options, arguments) = getopt.getopt(sys.argv[1:], "c:h:ds:t:")
    debug = 0;
    for (switch, val) in options:
        if (switch == '-c'):
                shorthands["class"] += r"|\b" + val + r"\b"
        elif (switch == '-d'):
            debug += 1
        elif (switch == '-h'):
                for line in open(val):
                    process_hint(line)
        elif (switch == '-s'):
                stringify.append(val)
        elif (switch == '-t'):
                shorthands["type"] += r"|\b" + val + r"\b" 

    try:
        code = sys.stdin.read()
        if debug >= 2:
            print("Input is: %s" % 'code')
        text = ctopy(code)
        if debug:
            print("Output:")
        sys.stdout.write(text)
    except KeyboardInterrupt:
        pass


class ctopy_t(abyss_filter_t):
    """experimental filter that demonstrates how
    to modify decompiled text on the fly."""

    def process_text(self, cfunc):
        pc = cfunc.get_pseudocode()
        lines = "\n".join([ida_lines.tag_remove(sl.line) for sl in pc])
        py = ctopy(lines)
        pc.clear()
        sl = ida_kernwin.simpleline_t()
        for line in py.splitlines():
            sl.line = line
            pc.push_back(sl)
        return 0

def FILTER_INIT():
    return ctopy_t()