from binaryninja import *

COULD_NOT_FIX = 0
DID_NOT_HAVE_TO_FIX = 0

def progress(cur, total):
    pass

def transform_func_type(type, func_name, function):
    current_type = type
    
    int_params = ["d4", "d5", "d6", "d7"]
    ptr_params = ["a4", "a5", "a6", "a7"]
    if "enum" in current_type and "{" in current_type:
        log_warn(f"[!] Cannot automatically fixup the function: {func_name}")
        return None
    if "struct" in current_type and "{" in current_type:
        for param in func.parameter_vars:
            type_string = str(param.type)
            if "struct" in type_string and "{" in type_string:
                struct_start = type_string.split("{")[0]
                struct_end = type_string.split("}")[-1]
                if ";" not in struct_end:
                    type_string = type_string.replace(struct_end,"")
                new_type_name = f"{param.name}_TC_AUTOTYPE"
                if current_type.find(type_string) == -1:
                    log_warn(f"[!] Cannot automatically fixup the function: {func_name}")
                    return None
                current_type = current_type.replace(type_string, new_type_name)
                type_string = type_string.replace(struct_start, f"{struct_start}{new_type_name} ",1).replace("struct const","struct")
                try:
                    tps = bv.platform.parse_types_from_source(f"{type_string};")
                    for name in tps.types:
                        log_info(f"[*] Adding new type: {name}")
                    bv.define_user_types([(x,tps.types[x]) for x in tps.types],progress)
                except SyntaxError:
                    log_warn(f"[!] Adding type failed: {func_name}")
                    return None
    if ")()" in current_type:
        log_warn(f"[!] Cannot automatically fixup the function: {func_name}")
        return None
    
    if "@" in current_type:
        return None # Do not touch the function if it already has some params assigned
    mod_type = current_type.split(")")[0].split("(")[1]
    params_list = mod_type.split(",")
    ret_val = current_type.split("(")[0]
    ptr_ctr = sum(1 for p in params_list if "*" in p)
    int_ctr = sum(1 for p in params_list if "*" not in p)
    
    if int_ctr < 5 and ptr_ctr < 5:
        for param in params_list:
            if param:
                if "*" in param:
                    mod_type = mod_type.replace(param, f"{param} @ {ptr_params.pop(0)}")
                else:
                    mod_type = mod_type.replace(param, f"{param} @ {int_params.pop(0)}")
            else:
                return False
    else:
        return None
    if "struct" in ret_val:
        func.comment = f"This function original type returned '{ret_val}'"
        ret_val = "void*"
    return f"{ret_val} {func_name}({mod_type})"


total_len = len(list(bv.functions))
for func in bv.functions:
    if func.name.startswith("sub_") or func.name.startswith("j_sub_"):
        continue
    new_func_type = transform_func_type(str(func.type),func.name, func)
    if new_func_type == None:
        COULD_NOT_FIX += 1
    elif new_func_type == False:
        DID_NOT_HAVE_TO_FIX += 1
    elif new_func_type:
        try:
            func.type = new_func_type
            log_info(f"[*] Changing type from: '{func.type}' to '{new_func_type}'.")
        except SyntaxError:
            log_warn(f"[*] Cannot change type from: '{func.type}' to '{new_func_type}'.")
            COULD_NOT_FIX += 1


log_info(f"Could not fix: {COULD_NOT_FIX}, did not have to fix: {DID_NOT_HAVE_TO_FIX} out of total {total_len}")
