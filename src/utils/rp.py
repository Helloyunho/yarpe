from constants import FONT_PATH, rp

__all__ = ["log", "log_exc"]

debug_log = []
exception_occurred = False


def delete_last_line(event, interact=True, **kwargs):
    global debug_log
    global exception_occurred
    if len(debug_log) > 0 and exception_occurred and interact and event == "end":
        exception_occurred = False
        debug_log.pop()


debug_char = rp.store.Character(
    None,
    callback=delete_last_line,
    what_color="#00ff00",
    what_size=18,
    what_font=FONT_PATH,
    what_xalign=0.0,
    what_yalign=0.0,
    what_outlines=[(2, "#000000", 0, 0)],
    what_background=rp.store.Solid("#000000"),
    ctc=None,
    ctc_pause=None,
    ctc_timedpause=None,
    what_slow_cps=0,
    window_background=rp.store.Solid("#000000"),
    window_xfill=True,
    window_yfill=True,
    window_xalign=0.0,
    window_yalign=0.0,
    window_left_padding=20,
    window_top_padding=20,
    window_left_margin=0,
    window_right_margin=0,
    window_top_margin=0,
    window_bottom_margin=0,
)


def log(*args):
    global debug_log
    strings = " ".join([str(arg) for arg in list(args)]).split("\n")
    debug_log.extend(strings)
    if len(debug_log) > 32:
        debug_log = debug_log[-32:]
    full_msg = "{nw}" + "\n".join(debug_log)
    rp.game.invoke_in_new_context(debug_char, full_msg)


def log_exc(string):
    global exception_occurred
    log("{b}[EXCEPTION] " + string + "{/b}")
    exception_occurred = True
    log("An error occurred! Press X(or O) to continue.{w}")
