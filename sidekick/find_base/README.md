# Find Base

This script will attempt to find the base address of the firmware image from provided flash memory address range. **Please note that this script requires that the image is initially loaded to offset 0x0!** It will print the guessed offset to the console.
It is recommended to start at offset `0x100` if the detected base does not seem to be correct, decrease the number to `0x10`.