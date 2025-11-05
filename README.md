# yarpe

Yet another Ren'Py PlayStation exploit

## Supported games

- A YEAR OF SPRINGS PS4 (CUSA30428)

## How to use

Thanks https://github.com/shahrilnet/remote_lua_loader/blob/main/SETUP.md for the base of this guide.

### "Pickling" the save data (Can be skipped if you download the pre-made save file from releases)
 - Prerequisites: Python 2.7.18
 - Run `python2 pack_savegame.py` to generate `1-1-LT1.save`.

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
    - `sc.errno`: Last error number.
    - `sc.run_function(address, rdi, rsi, rdx, rcx, r8, r9, syscall=False, ...)`: Runs the function at `address` with given arguments.
    - `sc.get_error_string()`: Returns the last error string.
    - `sc.send_notification(message)`: Sends a notification to the PS4/PS5.
- `readbuf(addr, length)`: Reads `length` bytes from `addr`.
- `readuint(addr, size)`: Reads an unsigned integer of `size` bytes from `addr`.
- `refbytes(data)`: Returns a pointer to the content of bytes object `data` that can then be passed to functions.
- `refbytearray(data)`: Returns a pointer to the content of bytearray object `data` that can then be passed to functions.

## Credits
- [@DrYenyen](https://github.com/DrYenyen) - Testing with me
- [@Gezine](https://github.com/Gezine) - For giving me some important clues
- [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader) - Being the reference for things like syscall
- And anyone else who helped me!

## Disclaimer
This project is for educational purposes only. The author is not responsible for any damage caused by the use of this project.
