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
    with open_index(bv, f"Undiscovered XREFs to {target_func_name}") as index:
        for current_address in range(start_addr,end_addr,bv.arch.instr_alignment):
            notify_progress(current_address - start_addr, end_addr - start_addr, 'Trying to find unknown XREFs')
            if not bv.get_functions_containing(current_address):
                data = bv.read(current_address,bv.arch.max_instr_length)
                instruction = bv.arch.get_instruction_info(data,current_address)
                if instruction:
                    for branch in instruction.branches:
                        if branch.target == target_func_addr:
                            bv.define_user_data_var(current_address,"uint32_t")
                            index.add_entry(bv.get_data_var_at(current_address),{"Potential XREF at": hex(current_address)})
                            #log_info(f"GOT CALL TO FUNC THAT IS NOT RECOGNIZED @ {hex(current_address)}")
                            total_calls += 1

    print(f"Total new calls discovered: {total_calls}")