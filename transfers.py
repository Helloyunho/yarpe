import sys
import json


def recv_xfer(sock):
    """
    Receives XFER block:

        __XFER_BEGIN__
        TYPE:<type>
        NAME:<name>
        SIZE:<size>
        __XFER_START__
        <raw bytes>
        __XFER_END__

    Implements:
      - progress bar (if SIZE >= 0)
      - size validation
    """
    header_buf = ""

    # Wait for header
    while "__XFER_BEGIN__" not in header_buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, None, None
        try:
            header_buf += chunk.decode("utf-8", "ignore")
        except:
            return None, None, None

    lines = header_buf.splitlines()
    try:
        idx = lines.index("__XFER_BEGIN__")
    except ValueError:
        return None, None, None

    x_type = None
    name = None
    declared_size = -1

    # Parse metadata
    for line in lines[idx+1:]:
        if line.startswith("TYPE:"):
            x_type = line[5:]
        elif line.startswith("NAME:"):
            name = line[5:]
        elif line.startswith("SIZE:"):
            try:
                declared_size = int(line[5:])
            except:
                declared_size = -1
        elif line == "__XFER_START__":
            break

    raw = bytearray()
    show_progress = (declared_size >= 0)

    # Progress banner
    if show_progress:
        sys.stdout.write("Receiving %d bytes...\n" % declared_size)
        sys.stdout.flush()

    # Read payload
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break

        raw.extend(chunk)

        # detect end marker
        pos = raw.find(b"__XFER_END__")
        if pos != -1:
            raw = raw[:pos]
            break

        # live progress bar
        if show_progress:
            received = len(raw)
            if declared_size > 0:
                pct = int((received * 100) / declared_size)
                if pct > 100:
                    pct = 100
                bar_len = 40
                filled = int((pct * bar_len) / 100)
                bar = "#" * filled + "." * (bar_len - filled)
                sys.stdout.write("\r[%s] %d%% (%d/%d)" %
                                 (bar, pct, received, declared_size))
                sys.stdout.flush()

    if show_progress:
        sys.stdout.write("\n")
        sys.stdout.flush()

    # Size validation
    if declared_size >= 0:
        actual = len(raw)
        if actual != declared_size:
            sys.stdout.write("[WARNING] Expected %d bytes but received %d bytes.\n" %
                             (declared_size, actual))
            sys.stdout.flush()

    return x_type, name, raw


# ----------------------------------------------------------
# SAVING FUNCTIONS
# ----------------------------------------------------------

def save_bin(name, raw):
    fn = name + ".bin"
    with open(fn, "wb") as f:
        f.write(raw)
    print("[saved BIN to %s]" % fn)


def save_text(name, raw):
    fn = name + ".txt"
    with open(fn, "w") as f:
        f.write(raw.decode("utf-8", "ignore"))
    print("[saved TEXT to %s]" % fn)


def save_kv(name, raw):
    fn = name + ".txt"
    with open(fn, "w") as f:
        f.write(raw.decode("utf-8", "ignore"))
    print("[saved KV to %s]" % fn)


def save_json(name, raw):
    """
    raw contains lines: repr_key:repr_value
    """
    text = raw.decode("utf-8", "ignore")
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        try:
            k = eval(parts[0])
            v = eval(parts[1])
            out[k] = v
        except:
            pass

    fn = name + ".json"
    with open(fn, "w") as f:
        json.dump(out, f, indent=2)
    print("[saved JSON to %s]" % fn)


def save_raw(name, raw):
    fn = name + ".raw"
    with open(fn, "wb") as f:
        f.write(raw)
    print("[saved RAW to %s]" % fn)


def handle_xfer(x_type, name, raw):
    """Dispatch saving based on type."""
    if not name:
        name = "dump"

    if x_type == "BIN":
        save_bin(name, raw)
    elif x_type == "TEXT":
        save_text(name, raw)
    elif x_type == "KV":
        save_kv(name, raw)
    elif x_type == "JSON":
        save_json(name, raw)
    else:
        save_raw(name, raw)
