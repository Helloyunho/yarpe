import base64
import pickle
import renpy
import zipfile
import os

version = os.getenv("YARPE_VERSION", "custom build")

SCRIPT = """
import struct
import sys
import traceback
import zipfile
import os
import base64
import io

B64_ZIP = "%s"

# the game changes path like `foo/bar/baz` to `_foo__bar_baz`
# since the zip already has converted name, we need to reverse that
def filename_converter(name):
    pattern = re.compile(r"_([a-zA-Z0-9]+)_")
    paths = pattern.split(name)
    return "/".join(paths)


def save_index_parser(data):
    files = dict()
    count = struct.unpack("<I", data[0:4])[0]
    offset = 4
    for _ in range(count):
        skip = struct.unpack("<Q", data[offset : offset + 8])[0]
        offset += 8
        name_len = struct.unpack("<I", data[offset : offset + 4])[0]
        offset += 4
        name = data[offset : offset + name_len].decode("utf-8")
        offset += name_len + 1  # null terminator
        split_path = name[7:].split("/")  # remove leading /saves/
        files[
            "".join(
                [
                    ("_%%s_" %% x) if i != len(split_path) - 1 else x
                    for i, x in enumerate(split_path)
                ]
            )
        ] = name

    return files

with zipfile.ZipFile(io.BytesIO(base64.b64decode(B64_ZIP)), "r") as zipf:
    save_index = save_index_parser(zipf.read("-saveindex"))
    for fileinfo in zipf.infolist():
        if fileinfo.filename == "-saveindex":
            continue
        new_path = save_index.get(fileinfo.filename, fileinfo.filename)
        print("Extracting %%s (%%d bytes)" %% (new_path, fileinfo.file_size))
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path))
        with open(new_path, "wb") as f:
            f.write(zipf.read(fileinfo.filename))

renpy.invoke_in_new_context(narrator, "yarpe %s applied successfully. Please restart the game to apply changes.")

""" % (
    base64.b64encode(open("save.zip", "rb").read()).decode("utf-8"),
    version,
)


class Yummy(object):
    def __reduce__(self):
        return renpy.python.py_exec, (SCRIPT,)


def main():
    pickled = pickle.dumps(Yummy(), protocol=2)
    with open("savegame_container/log", "wb") as f:
        f.write(pickled)

    with zipfile.ZipFile("1-1-LT1_unzipper.save", "w") as zip:
        zip.write("savegame_container/extra_info", "extra_info")
        zip.write("savegame_container/json", "json")
        zip.write("savegame_container/log", "log")
        zip.write("savegame_container/renpy_version", "renpy_version")
        zip.write("savegame_container/screenshot.png", "screenshot.png")


if __name__ == "__main__":
    main()
