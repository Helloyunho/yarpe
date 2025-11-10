import renpy
import os
from offsets import GADGET_OFFSETS, LIBC_OFFSETS, EXEC_OFFSETS

VERSION = ""
with open(renpy.config.savedir + "/yarpe/version.txt", "r") as f:
    VERSION = f.read().strip()

FONT_PATH = renpy.config.savedir + "/yarpe/debug_mono.ttf"

CONSOLE_KIND = os.getenv("CONSOLE_KIND", None)
if CONSOLE_KIND is None:
    raise Exception("Cannot determine console kind")

SELECTED_GADGETS = GADGET_OFFSETS.get(renpy.config.name, {}).get(CONSOLE_KIND, {})
SELECTED_LIBC = LIBC_OFFSETS.get(renpy.config.name, {}).get(CONSOLE_KIND, {})
SELECTED_EXEC = EXEC_OFFSETS.get(renpy.config.name, {}).get(CONSOLE_KIND, {})

if not SELECTED_GADGETS or not SELECTED_LIBC or not SELECTED_EXEC:
    raise Exception("Unsupported game / console kind combination")

SYSCALL = {
    "read": 3,
    "write": 4,
    "open": 5,
    "close": 6,
    "accept": 30,
    "pipe": 42,
    "socket": 97,
    "bind": 104,
    "setsockopt": 105,
    "listen": 106,
    "getsockname": 118,
    "netgetiflist": 125,
    "sysctl": 202,
}

nogc = []

rp = renpy
