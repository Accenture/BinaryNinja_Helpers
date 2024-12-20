from binaryninja import *


def get_matching_neighbors(prev_addr, current_addr, next_addr):
    prev_diff = current_addr - prev_addr
    next_diff = next_addr - current_addr
    func_list = list(bv.functions)
    for func_index in range(1,len(func_list) - 1):
        cf_prev_diff = func_list[func_index].start - func_list[func_index - 1].start
        cf_next_diff = func_list[func_index + 1].start - func_list[func_index].start
        if cf_prev_diff == prev_diff and next_diff == cf_next_diff:
            return func_list[func_index]
    return None

filename = interaction.get_open_filename_input("Select file with kernel symbols:")
if not filename:
    print("You must provide the file with symbols!")
else:
    with open(filename,"r") as symbols_file:
        data = symbols_file.readlines()
        symbols = {}
        lines_to_parse = len(data)
        line_count = 0
        for line in data:
            line_count += 1
            notify_progress(line_count, lines_to_parse, 'Parsing the kallsyms file ...')
            line_split = line.split(" ")
            s_addr, s_type, s_name = line_split
            if "\t" in s_name:
                s_name, s_module = s_name.split("\t")
                s_module = s_module.strip()[1:-1]
            else:
                s_module = "Kernel"
            if s_module not in symbols:
                symbols[s_module] = []
            symbols[s_module].append({"s_name": s_name, "s_type": s_type, "s_addr": int(s_addr,16)})

        for module in symbols:
            symbols[module] = sorted(symbols[module], key=lambda x: x['s_addr'])
            symbol_count = 0
            for symbol in symbols[module]:
                symbol_count += 1
                notify_progress(symbol_count, len(symbols[module]), 'Making sure that all functions were detected properly ...')
                if len(bv.get_functions_containing(symbol["s_addr"])) == 0:
                    if symbol["s_addr"] >= bv.start and symbol["s_addr"] < bv.end:
                        bv.add_function(symbol["s_addr"])
        # Wait for analysis
        bv.reanalyze()
        notify_progress(0, 1, 'Reanalyzing the binary ...')
        while bv.analysis_progress.state != 2:
            pass
        total_rename_count = 0
        for module in symbols:
            symbols[module] = sorted(symbols[module], key=lambda x: x['s_addr'])
            symbol_count = 0
            for symbol in symbols[module]:
                symbol_count += 1
                notify_progress(symbol_count, len(symbols[module]), 'Renaming functions ...')
                func_at_addr = bv.get_functions_containing(symbol["s_addr"])
                if len(func_at_addr) == 1:
                    total_rename_count += 1
                    if module != "Kernel":
                        func_at_addr[0].name = f"{symbol["s_name"]}_[{module}]"
                    else:
                        func_at_addr[0].name =  symbol["s_name"]
                elif symbol["s_addr"] >= bv.start and symbol["s_addr"] < bv.end:
                    print(f"[!] No matching function found at {hex(symbol["s_addr"])} - it should be {symbol["s_name"]}")
        if total_rename_count == 0:
            modules_list = list(symbols.keys())
            selected_module = interaction.get_choice_input("There were no matches for any of the functions from the kallsyms file.\nIt seems like the image is incomplete or loaded to wrong address.\nTry to select specific module that you suspect that this file represents.", "Module selection", modules_list)
            if selected_module:
                symbol_count = 0
                '''if symbols[modules_list[selected_module]][0]["s_addr"] >= bv.start and symbols[modules_list[selected_module]][0]["s_addr"] < bv.end:
                    # Ensure that all symbosl are defined
                    selected_symbols_len = len(symbols[modules_list[selected_module]])
                    symbol_count = 0
                    for symbol in symbols[modules_list[selected_module]]:
                        symbol_count += 1
                        notify_progress(symbol_count, selected_symbols_len, 'Making sure that all functions were detected properly ...')
                        if len(bv.get_functions_containing(symbol["s_addr"])) == 0:
                            bv.add_function(symbol["s_addr"])
                    # Wait for analysis
                    bv.reanalyze()
                    notify_progress(0, 1, 'Reanalyzing the binary ...')
                    while bv.analysis_progress.state != 2:
                        pass
                    for symbol_index in range(0,len(symbols[modules_list[selected_module]])):
                        symbol_count += 1
                        notify_progress(symbol_count, selected_symbols_len, 'Renaming functions ...')
                        symbol = symbols[modules_list[selected_module]][symbol_index]
                        try:
                            func_to_rename = bv.get_functions_containing(symbol["s_addr"])[0]
                            func_to_rename.name = symbol["s_name"]
                        except IndexError:
                            print(f"[?] Function at address {hex(symbol["s_addr"])} was not defined.")'''
                diff = 0
                for symbol_index in range(1,len(symbols[modules_list[selected_module]])-1):
                    symbol = symbols[modules_list[selected_module]][symbol_index]
                    matched_func = get_matching_neighbors(symbols[modules_list[selected_module]][symbol_index-1]["s_addr"], symbol["s_addr"], symbols[modules_list[selected_module]][symbol_index+1]["s_addr"])
                    if matched_func:
                        diff = symbol["s_addr"] - matched_func.start
                        matched_diff = True
                        for symbol in symbols[modules_list[selected_module]]:
                            existing_funcs = bv.get_functions_containing(symbol["s_addr"] - diff)
                            if len(existing_funcs) > 0:
                                if existing_funcs[0].start != symbol["s_addr"] - diff:
                                    matched_diff = False
                        if matched_diff:
                            break
                        #break
                
                for symbol in symbols[modules_list[selected_module]]:
                    bv.add_function(symbol["s_addr"] - diff)
                bv.reanalyze()
                notify_progress(0, 1, 'Reanalyzing the binary ...')
                while bv.analysis_progress.state != 2:
                    pass
                for symbol in symbols[modules_list[selected_module]]:
                    try:
                        func_to_rename = bv.get_functions_containing(symbol["s_addr"] - diff)[0]
                        func_to_rename.name = symbol["s_name"]
                    except IndexError:
                        print(f"[!] No matching function found at {hex(symbol["s_addr"] - diff)} - it should be {symbol["s_name"]}")