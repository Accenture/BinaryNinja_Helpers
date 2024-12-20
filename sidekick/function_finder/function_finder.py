from binaryninja import *
from collections import Counter

target_func_addr = current_function.start
target_func_name = current_function.name

segments_list = [(s.start,s.end) for s in bv.segments if s.executable]
segment_choice = get_large_choice_input("Select Segment for Search", "Select Segment", [f"{hex(s[0])} - {hex(s[1])}" for s in segments_list])
if segment_choice != None:
    start_addr = segments_list[segment_choice][0]
    end_addr = segments_list[segment_choice][1]
    total_calls = 0
    addr_refs = 0
    with open_index(bv, f"Undiscovered XREFs to {target_func_name}") as index:
        for raw_ptr in bv.find_all_data(start_addr,end_addr,target_func_addr.to_bytes(bv.arch.address_size, "little" if bv.arch.endianness == Endianness.LittleEndian else "big")):
            if not bv.get_data_var_at(raw_ptr[0]):
                bv.define_user_data_var(raw_ptr[0],"void*")
            index.add_entry(bv.get_data_var_at(raw_ptr[0]),{"XREF Type": "Raw pointer address"})
            addr_refs += 1
        for current_address in range(start_addr,end_addr,bv.arch.instr_alignment):
            notify_progress(current_address - start_addr, end_addr - start_addr, 'Trying to find unknown XREFs')
            if not bv.get_functions_containing(current_address):
                data = bv.read(current_address,bv.arch.max_instr_length if bv.arch.max_instr_length >= 4 else 4)
                instruction = bv.arch.get_instruction_info(data,current_address)
                if instruction:
                    for branch in instruction.branches:
                        if branch.target == target_func_addr:
                            bv.define_user_data_var(current_address,"uint32_t")
                            index.add_entry(bv.get_data_var_at(current_address),{"XREF Type": "Call instruction"})
                            #log_info(f"GOT CALL TO FUNC THAT IS NOT RECOGNIZED @ {hex(current_address)}")
                            total_calls += 1

    print(f"New calls discovered: {total_calls}")
    print(f"Direct address refrences found: {addr_refs}")