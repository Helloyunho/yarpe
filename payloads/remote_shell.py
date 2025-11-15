from __future__ import print_function

import sys
import traceback
from StringIO import StringIO
from utils.conversion import u64_to_i64
from utils.etc import alloc
from utils.rp import log
from sc import sc


WRITING = False

if WRITING:  # solo para que el editor se calle
    port = 0
    s = 0
    sockaddr_in = bytearray()
    len_buf = bytearray()


PROMPT = "ps> "
END_MARKER = "\n<<<END_OF_RESULT>>>\n"


def handle_special_commands(cmd, ctx):
    """
    Comandos especiales tipo:
      .exit / .quit
      .vars         -> lista de nombres en el contexto
      .dir nombre   -> dir(nombre)
      .type nombre  -> type(nombre)
      .repr nombre  -> repr(nombre)
    """
    stripped = cmd.strip()

    if stripped in (".exit", "exit()", "quit()", ".quit"):
        log("Exit requested.")
        raise SystemExit

    # .vars -> mostrar keys de ctx
    if stripped == ".vars":
        names = sorted(ctx.keys())
        out = "Context variables:\n" + ", ".join(names) + "\n"
        return out, ""

    # .dir nombre
    if stripped.startswith(".dir "):
        name = stripped[5:].strip()
        if name in ctx:
            obj = ctx[name]
            out = "dir(%s):\n%s\n" % (name, ", ".join(dir(obj)))
        else:
            out = "Name %r not found in context.\n" % name
        return out, ""

    # .type nombre
    if stripped.startswith(".type "):
        name = stripped[6:].strip()
        if name in ctx:
            obj = ctx[name]
            out = "type(%s): %r\n" % (name, type(obj))
        else:
            out = "Name %r not found in context.\n" % name
        return out, ""

    # .repr nombre
    if stripped.startswith(".repr "):
        name = stripped[6:].strip()
        if name in ctx:
            obj = ctx[name]
            out = "repr(%s): %r\n" % (name, obj)
        else:
            out = "Name %r not found in context.\n" % name
        return out, ""

    # Ningún comando especial
    return None, None


def handle_command(cmd, ctx):
    log("handle_command() received cmd=%r" % cmd)

    cmd = cmd.rstrip("\n")
    if not cmd:
        log("Empty command.")
        return "", ""

    # Primero intentamos comandos especiales tipo .dir, .vars, etc.
    special_out, special_err = handle_special_commands(cmd, ctx)
    if special_out is not None or special_err is not None:
        return special_out or "", special_err or ""

    stdout_buf = StringIO()
    stderr_buf = StringIO()

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = stdout_buf
    sys.stderr = stderr_buf

    try:
        try:
            code_obj = compile(cmd, "<remote>", "eval")
            mode = "eval"
            log("Compiled as eval.")
        except SyntaxError:
            code_obj = compile(cmd, "<remote>", "exec")
            mode = "exec"
            log("Compiled as exec.")

        try:
            if mode == "eval":
                result = eval(code_obj, ctx, ctx)
                # Para ver contenido de expresiones tipo "renpy"
                if result is not None:
                    print(repr(result))
            else:
                exec(code_obj, ctx, ctx)
        except SystemExit:
            raise
        except Exception:
            log("Exception while running code.")
            traceback.print_exc(file=stderr_buf)
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    out = stdout_buf.getvalue()
    err = stderr_buf.getvalue()

    if out:
        log("stdout=%r" % out)
    if err:
        log("stderr=%r" % err)

    return out, err


# -----------------------------------------------------
#  ACCEPT CONNECTION (reuse Stage-1 listener socket!)
# -----------------------------------------------------
buf1 = alloc(1)

client_sock = u64_to_i64(sc.syscalls.accept(s, sockaddr_in, len_buf))

# Send greeting
greeting = (
    "Remote Python console ready (Python 2.7).\n"
    "Reusing Stage-1 listener socket.\n"
    "Special commands: .exit, .quit, .vars, .dir name, .type name, .repr name\n"
)
sc.syscalls.write(client_sock, greeting, len(greeting))

log("Accepted client_sock=%d" % client_sock)

ctx = globals()
log("Globals loaded into REPL context.")

# -----------------------------------------------------
#  REPL LOOP
# -----------------------------------------------------
while True:
    log("Writing prompt.")
    sc.syscalls.write(client_sock, PROMPT, len(PROMPT))

    log("Reading command bytes...")
    cmd_bytes = ""

    # Read command line (1 byte at a time, buf1 es bytearray)
    while True:
        n = u64_to_i64(sc.syscalls.read(client_sock, buf1, 1))
        log("read() returned %d" % n)

        if n <= 0:
            log("read <= 0, closing.")
            sc.syscalls.close(client_sock)
            raise SystemExit

        # buf1[0] es un int 0–255; lo convertimos a char
        c = chr(buf1[0])
        log("Received raw byte: %r" % c)

        cmd_bytes += c

        if c == "\n":
            log("Newline detected, end of command.")
            break

    # Now decode
    log("Decoding cmd_bytes=%r" % cmd_bytes)
    try:
        cmd = cmd_bytes.decode("utf-8", "replace")
    except Exception as e:
        log("DECODE ERROR: %s" % e)
        cmd = ""

    log("Decoded command: %r" % cmd)

    # Execute command
    try:
        out, err = handle_command(cmd, ctx)
    except SystemExit:
        bye = "Bye.\n"
        sc.syscalls.write(client_sock, bye, len(bye))
        sc.syscalls.close(client_sock)
        break

    # Send results
    result = out + err
    if result:
        log("Sending result len=%d" % len(result))
        sc.syscalls.write(client_sock, result, len(result))

    sc.syscalls.write(client_sock, END_MARKER, len(END_MARKER))
    log("END_MARKER sent.")
