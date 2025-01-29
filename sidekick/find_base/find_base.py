from binaryninja import *


def intersect(a, b):
    return list(set(a) & set(b))

ptrs_to_flash = []
func_addrs = []

start = interaction.TextLineField("MCU flash region start in hex:")
end = interaction.TextLineField("MCU flash region end in hex:")
step = interaction.TextLineField("Step for the offset search in hex:")
if interaction.get_form_input([start,end,step],"Find Base"):
    flash_start_addr = int(start.result,16)
    flash_end_addr = int(end.result,16)
    offset_step = int(step.result,16)
    for func in bv.functions:
        func_addrs.append(func.start)
    for curr_addr in range(bv.start,bv.end,bv.address_size):
        notify_progress(curr_addr - bv.start, bv.end - bv.start, 'Gathering hardcoded pointers')
        data = bv.read(curr_addr,bv.address_size)
        extracted_addr = int.from_bytes(data,"little" if bv.arch.endianness == Endianness.LittleEndian else "big")
        if extracted_addr >= flash_start_addr and extracted_addr < flash_end_addr:
            ptrs_to_flash.append(extracted_addr)
    # Got list of all potential hardcoded pointers and all current function addresses
    # FInding the offset now
    best_offset = flash_start_addr
    best_offset_matches = 0
    for potential_offset in range(flash_start_addr, flash_end_addr-bv.length,offset_step):
        notify_progress(potential_offset - flash_start_addr, flash_end_addr-bv.length - flash_start_addr, 'Trying to figure out the base address')
        offseted_func_addrs = [i+potential_offset for i in func_addrs]
        current_offset_matches = len(intersect(offseted_func_addrs,ptrs_to_flash))
        if current_offset_matches > best_offset_matches:
            best_offset_matches = current_offset_matches
            best_offset = potential_offset
            #print(f"New best match at offset {hex(best_offset)} with {best_offset_matches}")
    print(f"Best matching offset is: {hex(best_offset)} with {best_offset_matches} matches")

