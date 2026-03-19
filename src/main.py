import traceback
import time
import os
import pygame_sdl2
from pygame_sdl2 import CONTROLLER_BUTTON_Y
from utils.fs import file_exists, read_file_data
from utils.rp import log, log_exc, payload_log
from utils.tcp import (
    create_tcp_client,
    create_tcp_server,
    accept_client,
    get_socket_name,
    read_all_from_socket,
    close_socket,
    write_to_socket,
)
from constants import CONSOLE_KIND, SHARED_VARS, rp
from sc import sc

"""
What it does:

1. leaks addresses of important functions / gadgets
2. builds a call primitive that can call any function with up to 6 args
3. provides basic read/write primitives

"""

PORT = 9025


def poc():
    log("[*] Detected game: %s %s" % (rp.config.name, CONSOLE_KIND))
    log("[*] Console: %s %s" % (sc.platform.upper(), sc.version))

    AUTO_LOAD_PATHS = []
    for i in range(8):
        AUTO_LOAD_PATHS.append("/mnt/usb%d/yarpe_autoload/autoload.txt" % i)
    AUTO_LOAD_PATHS.append("/data/yarpe_autoload/autoload.txt")
    AUTO_LOAD_PATHS.append("/saves/yarpe_autoload/autoload.txt")

    auto_load_path = None
    run_auto_load = True
    for path in AUTO_LOAD_PATHS:
        if file_exists(path) or os.path.exists(path):
            auto_load_path = path
            break

    c = pygame_sdl2.controller.Controller(0)
    c.init()
    run_auto_load = c.get_button(CONTROLLER_BUTTON_Y) == 0
    c.quit()

    if run_auto_load and auto_load_path is not None:
        log("[*] Found autoload file at %s" % auto_load_path)
        log(
            "[*] Will execute autoload. You can skip autoload by holding the triangle button when loading the save."
        )
        try:
            SHARED_VARS["AUTO_LOAD"] = True
            loaded_from_save = auto_load_path.startswith("/saves/")
            if loaded_from_save:
                with open(auto_load_path, "r") as f:
                    auto_load_str = f.read()
            else:
                auto_load_str = read_file_data(auto_load_path).decode("utf-8")
            log("[*] Loaded autoload file from %s" % auto_load_path)
            auto_load_dir = os.path.dirname(auto_load_path)
            for line in auto_load_str.splitlines():
                line = line.strip()

                if line.startswith("#") or len(line) == 0:
                    continue
                elif line.startswith("!"):
                    # sleep command
                    sleep_time = float(line[1:].strip())
                    log("[*] Sleeping for %f milliseconds..." % sleep_time)
                    time.sleep(sleep_time / 1000.0)
                    continue

                exec_path = os.path.join(auto_load_dir, line)
                if (not loaded_from_save and file_exists(exec_path)) or os.path.exists(
                    exec_path
                ):
                    exec_ext = os.path.splitext(exec_path)[-1].lower()

                    if exec_ext == ".py":
                        log("[*] Executing autoload script: %s" % exec_path)

                        if loaded_from_save:
                            with open(exec_path, "r") as f:
                                exec_str = f.read()
                        else:
                            exec_str = read_file_data(exec_path).decode("utf-8")
                        scope = dict(globals(), **locals())
                        exec(exec_str, scope)

                        log("[*] Autoload script executed successfully: %s" % exec_path)
                    elif exec_ext in [".bin", ".elf"]:
                        if loaded_from_save:
                            with open(exec_path, "rb") as f:
                                exec_data = f.read()
                        else:
                            exec_data = read_file_data(exec_path)
                        log(
                            "[*] Executing autoload binary(assumes loader is already executed): %s"
                            % exec_path
                        )
                        if sc.platform == "ps5":
                            sock = create_tcp_client("127.0.0.1", 9021)
                            write_to_socket(sock, exec_data)
                            close_socket(sock)
                            log("[*] Killing game to allow elfldr to take over...")
                            sc.kill_game()
                        else:
                            BinLoader = SHARED_VARS.get("BinLoader", None)
                            if BinLoader is None:
                                log(
                                    "[!] BinLoader not found in SHARED_VARS, cannot execute binary: %s"
                                    % exec_path
                                )
                            else:
                                loader = BinLoader(exec_data)
                                loader.run()
                                loader.join()
                                log(
                                    "[*] Autoload binary executed successfully: %s"
                                    % exec_path
                                )
                    else:
                        log("[*] Unknown file detected, ignoring...")
        except:
            exc_msg = traceback.format_exc()
            log_exc(exc_msg)
        log("[*] Autoload finished. Continuing to socket listener...")
    else:
        log("[*] No autoload file found or autoload cancelled.")

    SHARED_VARS["AUTO_LOAD"] = False
    s = None
    port = None
    log("[*] Creating TCP socket...")
    s, sockaddr_in = create_tcp_server(PORT)

    _, port = get_socket_name(s)

    ip = sc.get_current_ip()

    if ip is None:
        msg = "Listening on port %d for stage 2 payload..." % port
        sc.send_notification(msg)
        log(msg)
    else:
        msg = "Listening on %s:%d for stage 2 payload..." % (ip, port)
        sc.send_notification(msg)
        log(msg)
    while True:
        log("Waiting for client connection...")
        client_sock = accept_client(s)

        log("Client connected on socket %d" % client_sock)

        stage2_str = read_all_from_socket(client_sock).decode("utf-8")

        log("Received payload, executing...")

        # Keep client_sock open so payload log can be sent back
        SHARED_VARS["client_sock"] = client_sock

        payload_log[:] = []

        # Execute code, mimic file-exec by throwing local/global in same scope
        scope = dict(globals(), **locals())
        try:
            exec(stage2_str, scope)
            log("Payload executed successfully")
        except:
            exc_msg = traceback.format_exc()
            log_exc(exc_msg)
        finally:
            try:
                if payload_log:
                    write_to_socket(client_sock, "".join(payload_log).encode("utf-8"))
            except Exception:
                pass
            payload_log[:] = []
            SHARED_VARS.pop("client_sock", None)
            close_socket(client_sock)

    close_socket(s)  # close listening socket


poc()
