from binaryninja import *
from collections import Counter

segments_list = [(s.start,s.end) for s in bv.segments if s.executable]
segment_choice = get_large_choice_input("Select Segment for Search", "Select Segment", [f"{hex(s[0])} - {hex(s[1])}" for s in segments_list])
if segment_choice != None:
    start_addr = segments_list[segment_choice][0]
    end_addr = segments_list[segment_choice][1]
    addr_refs = 0
    funcs_total = len(bv.functions)
    func_counter = 0
    print("[*] Check log window. Possible function XREFs that are currently part of existing function code will be linked there (becouse this window does not support double click to go).")
    for target_func in bv.functions:
        notify_progress(func_counter, funcs_total, 'Trying to find unknown XREFs')
        func_counter += 1
        target_func_addr = target_func.start
        for raw_ptr in bv.find_all_data(start_addr,end_addr,target_func_addr.to_bytes(bv.arch.address_size, "little" if bv.arch.endianness == Endianness.LittleEndian else "big")):
            if not bv.get_functions_containing(raw_ptr[0]):
                if not bv.get_data_var_at(raw_ptr[0]):
                    bv.define_user_data_var(raw_ptr[0],"void*")
                    addr_refs += 1
            else:
                log_info(f"[?] There may be direct address reference at {hex(raw_ptr[0])}.")
    print(f"[*] Found total of {addr_refs} new direct address references!")
