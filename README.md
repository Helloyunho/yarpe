# yarpe

Yet another Ren'Py PlayStation exploit

> [!IMPORTANT]
> This exploit is userland exploit. Don't expect homebrew enabler(HEN) level of access.

## ToC
- [Supported games](#supported-games)
- [How to use](#how-to-use)
    - ["Pickling" the save data (Can be skipped if you download the pre-made save file from releases)](#pickling-the-save-data-can-be-skipped-if-you-download-the-pre-made-save-file-from-releases)
    - [Changing the save data on PS4/PS4 Slim/PS4 Pro/](#changing-the-save-data-on-ps4ps4-slimps4-pro)
        - [Jailbroken](#jailbroken)
        - [PSN(or fake)-Activated](#psnor-fake-activated)
    - [Changing the save data on PS5/PS5 Slim/PS5 Pro](#changing-the-save-data-on-ps5ps5-slimps5-pro)
    - [Run custom code on the game](#run-custom-code-on-the-game)
- [Python API](#python-api)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

## Supported games

- A YEAR OF SPRINGS PS4 (CUSA30428, CUSA30429, CUSA30430, CUSA30431)
- Arcade Spirits: The New Challengers PS4 (CUSA32096, CUSA32097)

## How to use

Thanks https://github.com/shahrilnet/remote_lua_loader/blob/main/SETUP.md for the base of this guide.

### "Pickling" the save data (Can be skipped if you download the pre-made save file from releases)
 - Run `python2 pack_savegame.py` to generate `1-1-LT1.save`.
    - You can set the `DEBUG` environment variable to `1` or `true` to enable debug messages.

> [!NOTE]
> You can also change the name of `savegame_container/log` to `persistent` and copy that instead of `1-1-LT1.save` if you want to execute the code immediately, but this makes the game unplayable until you delete the save data.

> [!NOTE]
> Guide below assumes you already made a save file in the game you want to modify.

### Changing the save data on PS4/PS4 Slim/PS4 Pro/

#### Jailbroken

1. Use Apollo Save Tool to export decrypted save data to USB drive by using the "Copy save game to USB" option.
2. Go to (/PS4/APOLLO/id_{YOUR_GAME_CUSA_ID}_savedata) and copy `1-1-LT1.save` to that folder, replacing the existing file.
3. Use Apollo Save Tool to import the new save data from USB drive with "Copy save game to HDD".
4. Run the game and see if the save data is changed(by looking at the save image).

#### PSN(or fake)-Activated

1. Make sure you're logged-in to the PSN(or fake)-activated user.
2. Connect your USB drive to the PS4/PS4 Slim/PS4 Pro.
3. Use the PS4 settings menu to export the save data to USB. (`Settings -> Application Saved Data Management -> Saved Data in System Storage -> Copy to USB Storage Device -> Select your game and copy`)
4. You should have `SAVEDATA00` and `SAVEDATA00.bin` files in `/PS4/SAVEDATA/(hash)/CUSA(your game id)/` on the USB drive. Use either Save Wizard or Discord bot to decrypt the save data.
5. Go to the decrypted save data folder and copy `1-1-LT1.save` to that folder, replacing the existing file.
6. Use either Save Wizard or Discord bot to encrypt the modified save data again.
7. Put the encrypted `SAVEDATA00` and `SAVEDATA00.bin` files back to `/PS4/SAVEDATA/(hash)/CUSA(your game id)/` on the USB drive.
8. Connect the USB drive to the PS4/PS4 Slim/PS4 Pro.
9. Use the PS4 settings menu to import the modified save data from USB. (`Settings -> Application Saved Data Management -> Saved Data on USB Storage Device -> Copy to System Storage -> Select your game and copy`)
10. Run the game and see if the save data is changed(by looking at the save image).

### Changing the save data on PS5/PS5 Slim/PS5 Pro

- Requirements:
    - PSN-activated PS5/PS5 Slim/PS5 Pro. Can be non-recent offline firmware if was activated in the past.
    - A PSN(or fake)-activated PS4 on a firmware version that is earlier or equivilant to the PS5/PS5 Slim/PS5 Pro. Refer to this [table](https://www.psdevwiki.com/ps5/Build_Strings). For example, PS4 9.00 can be used to create save game for PS5 >=4.00 but not below that.

#### Steps:
1. Find your logged-in PSN account id on the PS5/PS5 Slim/PS5 Pro. Either by going to the PlayStation settings or by using [this website](https://psn.flipscreen.games/).
2. Take your account ID number (~19 characters long, for PSPlay) and convert it to hex using [this website](https://www.rapidtables.com/convert/number/decimal-to-hex.html).

#### PS4
3. Follow the "PSN-Activated" PS4/PS4 Slim/PS4 Pro guide above until step 7 to export the save data to USB drive.

#### PSN-Activated PS5/PS5 Slim/PS5 Pro -
4. Make sure you're logged-in to the PSN-activated user.
5. Connect your USB drive to the PS5/PS5 Slim/PS5 Pro.
6. Use the PS5 settings menu to import the encrypted save data from the USB drive. (`Saved Data and Game/App Settings -> Saved Data (PS4) -> Copy or Delete from USB Drive -> Select your game and import`)
7. Run the game and see if the save data is changed(by looking at the save image).

### Run custom code on the game
1. Get any TCP socket client(e.g. nc, [hermes-link](https://github.com/Al-Azif/hermes-link)) on your PC.
2. Prepare a python script that you want to run on the game.
3. Send the script data to the console on port 9025.
4. The script will be executed on the game.

## Python API

- `sc`: SploitCore instance
    - `sc.functions`: Known functions that you can access like `sc.functions.function_name(arg1, arg2, ...)`.
    Arguments will be automatically converted to integers using `get_ref_addr()`.
    - `sc.syscalls`: Known syscalls that you can access like `sc.syscalls.syscall_name(arg1, arg2, ...)`.
    Arguments will be automatically converted to integers using `get_ref_addr()`.
    - `sc.errno`: Last error number.
    - `sc.exec_addr`: Base address of the game's executable in memory.
    - `sc.libc_addr`: Base address of libc in the game's memory.
    - `sc.libkernel_addr`: Base address of libkernel in the game's memory.
    - `sc.platform`: The console platform(does not depend on game edition) (e.g., 'ps4', 'ps5').
        - Do note that these are in lowercase.
    - `sc.version`: The console firmware version (e.g., '9.00', '10.03').
    - `sc.make_function_if_needed(name, addr)`: Creates a function entry in `sc.functions` if it does not already exist, and returns it.
    - `sc.make_syscall_if_needed(name, num)`: Creates a syscall entry in `sc.syscalls` if it does not already exist, and returns it.
    - `sc.send_notification(message)`: Sends a notification to the PS4/PS5.
    - `sc.get_sysctl_int(name)`: Gets the integer value of the sysctl variable `name`.
    - `sc.set_sysctl_int(name, value)`: Sets the integer value of the sysctl variable `name` to `value`.
- `ROPChain(sc, size=variable_per_console)`: Creates a ROP chain builder.
    - `ropchain.chain`: The bytearray representing the ROP chain.
    - `ropchain.index`: Current index in the ROP chain.
    - `ropchain.return_value`:
        - If `push_get_return_value()` was used, this will contain the return value of the function call after execution.
    - `ropchain.errno`:
        - If `push_get_errno()` was used, this will contain the errno value after execution.
    - `ropchain.addr`: The address of the ROP chain in memory.
    - `ropchain.reset()`: Resets the ROP chain to empty.
    - `ropchain.append(value)`: Appends the 8-byte `value` to the ROP chain.
    - `ropchain.extend(buf)`: Extends the ROP chain with the bytes in `buf`.
    - `ropchain.push_gadget(gadget_name)`: Appends the gadget with name `gadget_name` to the ROP chain.
    - `ropchain.push_value(value)`: Same as `append(value)`.
    - `ropchain.push_syscall(syscall_number, arg1, arg2, ...)`: Appends the syscall with number `syscall_number` and its arguments to the ROP chain.
    Arguments will be automatically converted to integers using `get_ref_addr()`.
    - `ropchain.push_call(addr, arg1, arg2, ...)`: Appends the function call to `addr` with its arguments to the ROP chain.
    Arguments will be automatically converted to integers using `get_ref_addr()`.
    - `ropchain.push_get_return_value()`: Appends the necessary gadgets to get the return value of the last function/syscall called.
    - `ropchain.push_get_errno()`: Appends the necessary gadgets to get the errno value after the last function/syscall called.
    - `ropchain.push_write_into_memory(addr, data)`: Appends the necessary gadgets to write `data` into memory at `addr`.
    - `ropchain.push_store_rax_into_memory(addr)`: Appends the necessary gadgets to store the value in `RAX` into memory at `addr`.
    - `ropchain.push_store_rdx_into_memory(addr)`: Appends the necessary gadgets to store the value in `RDX` into memory at `addr`.
- `Executable(sc, size=variable_per_console)`: Creates an executable memory region.
    - When you create an `Executable` instance, you need to create 4 ROP chains:
        - Front chain
        - Call/syscall chain
        - Post chain
        - Back chain
    - `executable.chain`: The `ROPChain` instance representing the executable code.
    - `executable.errno`: The errno value after execution.
    - `executable.setup_front_chain()`: Sets up the front chain for execution.
    - `executable.setup_call_chain(func_addr, arg1, arg2, ...)`: Sets up the call chain to call `func_addr` with its arguments.
    Arguments will be automatically converted to integers using `get_ref_addr()`.
    - `executable.setup_syscall_chain(syscall_number, arg1, arg2, ...)`: Sets up the syscall chain to call `syscall_number` with its arguments.
    Arguments will be automatically converted to integers using `get_ref_addr()`.
    - `executable.setup_post_chain()`: Sets up the post chain for execution.
    - `executable.setup_back_chain()`: Sets up the back chain for execution.
    - `executable.execute()`: Executes the code in the executable memory region.
- `Structure(structure_pair)`: Creates a structure definition from `structure_pair`.
    - `structure_pair = [(field_name1, field_size1), (field_name2, field_size2), ...]`
    - `structure.size`: Total size of the structure in bytes.
    - `structure.offsets`: A dictionary mapping field names to their offsets in the structure.
    - `structure.create(defaults=None)`: Creates an instance of the structure with optional defaults(`defaults[field] = value`).
    - `structure.from_bytes(data)`: Creates an instance of the structure from the given bytes `data`.
        - Do note that `data` will be copied into a new bytearray, so modifying the instance will not modify `data`.
    - `structure.from_bytearray(data)`: Creates an instance of the structure from the given bytearray `data`.
        - Do note that modifying the instance will modify `data` as well.
    - `structure.from_address(addr)`: Creates an instance of the structure from the memory at `addr`.
        - Do note that modifying the instance will modify the memory at `addr` as well.
- `StructureInstance(structure, defaults=None)`: Creates an instance of `structure`.
    - You can provide optional defaults(`defaults[field] = value`) to initialize fields.
    - When you access fields as attributes(e.g., `instance.field_name`), it will get/set the matching field value automatically.
    - `instance.structure`: The structure definition used to create this instance.
    - `instance.buf`: The bytearray representing the structure's data.
    - `instance.addr`: The address of the structure's data in memory.
    - `instance.get_field(field_name)`: Gets the value of the field `field_name`.
    - `instance.set_field(field_name, value)`: Sets the value of the field `field_name` to `value`.
    - `instance.get_field_raw(field_name, size)`: Gets the raw bytes of the field `field_name` with length `size`.
    - `instance.set_field_raw(field_name, data)`: Sets the raw bytes of the field `field_name` to `data`.
    - `instance.reset()`: Resets all fields to zero.
- `GADGET_OFFSETS`: A dictionary containing known gadget offsets that can be used in ROP chains.
    - Example: `GADGET_OFFSETS[game_name][console_variation][gadget_name] = offset`
- `LIBC_GADGETS`: A list that marks which gadgets are from libc.
    - For example, if you set `pop rax; ret` gadget as libc gadget, it will be resolved using `sc.libc_addr + offset` instead of `sc.exec_addr + offset`.
- `LIBC_OFFSETS`: A dictionary containing known libc function offsets that can be used to create function entries in `sc.functions`.
    - Example: `LIBC_OFFSETS[game_name][console_variation][function_name] = offset`
- `EXEC_OFFSETS`: A dictionary containing known executable function offsets that can be used to create function entries in `sc.functions`.
    - Example: `EXEC_OFFSETS[game_name][console_variation][function_name] = offset`
- `CONSOLE_KIND`: Current game console edition(e.g., 'PS4', 'PS5') (does not depend on the console model itself).
    - Do note that these are in uppercase.
- `SELECTED_GADGETS`: The gadget set selected for the current game and console.
- `SELECTED_LIBC`: The libc offsets selected for the current game and console.
- `SELECTED_EXEC`: The executable offsets selected for the current game and console.
- `SYSCALL`: A dictionary containing known syscall numbers that can be used to create syscall entries in `sc.syscalls`.
    - Example: `SYSCALL[syscall_name] = number`
- `readbuf(addr, length)`: Reads `length` bytes from `addr`.
- `readuint(addr, size)`: Reads an unsigned integer of `size` bytes from `addr`.
- `refbytes(data)`: Returns a pointer to the content of bytes object `data` that can then be passed to functions.
- `refbytearray(data)`: Returns a pointer to the content of bytearray object `data` that can then be passed to functions.
- `alloc(size)`: Allocates `size` bytes in the game's memory and returns the bytearray.
- `get_ref_addr(data)`: Returns the address of the content of bytes/bytearray object `data`.
- `SHARED_VARS`: A dictionary that can be used to share data between multiple payloads.

## Credits
- [@DrYenyen](https://github.com/DrYenyen) - Testing with me
- [@Gezine](https://github.com/Gezine) - For giving me some important clues
- [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader) - Being the reference for things like syscall
- And anyone else who helped me!

## Disclaimer
This project is for educational purposes only. The author is not responsible for any damage caused by the use of this project.
