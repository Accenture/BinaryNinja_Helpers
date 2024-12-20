
from binaryninja import *


def conditions(bv, cond, param):
    return eval(cond)

def no_guard(a, b, c, d, e):
    return False

def is_parameter_dynamic(call_insn: HighLevelILInstruction, param_index: int, multiparameter) -> bool:
    # TODO must do traceback here
    results = []
    if param_index == -1: # Bypass for functions where you dont care
        return False
    # Ensure the parameter index is within the bounds of the call's parameters
    if param_index >= len(call_insn.params):
        return False  # Index out of bounds
    if multiparameter:
        params = call_insn.params[param_index:]
    else:
        params = [call_insn.params[param_index]]
    for param in params:
        if not param.operation in [HighLevelILOperation.HLIL_CONST, HighLevelILOperation.HLIL_CONST_PTR]:
            results.append(True)
        else:
            results.append(False)
    return any(results)


def compare_param(a,b):
    if len(a.operands) != len(b.operands):
        return False
    if a.vars == b.vars:
        for op_index in range(0,len(a.operands)):
            if str(a.operands[op_index]) != str(b.operands[op_index]):
                return False
    return True


def has_func_guard(bv: BinaryView, call_insn: HighLevelILInstruction, param_index,func_list,multi_parameter):
    # TODO multiparam here
    if call_insn.operation != HighLevelILOperation.HLIL_CALL:
        return False

    # Check if the parameter index is within the range of the call's parameters
    if param_index >= len(call_insn.params):
        return False

    # Get the parameter variable
    param_var = call_insn.params[param_index]

    # Find the strlen function by name
    strlen_func = next((f for f in bv.get_functions_by_name('strlen')), None)
    if not strlen_func:
        return False
    # Iterate over all references to the parameter variable
    param_raw = call_insn.params[param_index]
    for param_var in call_insn.params[param_index].vars:
        for var_use in call_insn.function.get_var_uses(param_var):
            parent = var_use.parent
            while parent:
                # Look for calls in the HLIL instructions
                if parent.operation == HighLevelILOperation.HLIL_CALL:
                    # Check if the call is to strlen
                    # TODO change for simple string compare
                    func = bv.get_function_at(parent.dest.constant)
                    if parent.dest.operation == HighLevelILOperation.HLIL_CONST_PTR and func and func.name in func_list:
                        # Check if the parameter in question is used as an argument to strlen
                        for arg in parent.params:
                            if compare_param(param_raw,arg):
                                return True
                parent = parent.parent
    return False

def has_length_guard(bv: BinaryView, call_insn: HighLevelILInstruction, param_index,dummy=[],multi_parameter=False):
    guard_param = call_insn.params[param_index]

    if guard_param.operation in [HighLevelILOperation.HLIL_CONST, HighLevelILOperation.HLIL_CONST_PTR]:
        return False

    # Check for verification in preceding if conditions
    cur_block = call_insn.il_basic_block
    for block in bv.get_basic_blocks_at(cur_block.start):
        for insn in block:
            if insn.operation == HighLevelILOperation.HLIL_IF:
                condition = insn.condition
                # Simplistic check for a condition that compares the memcpy size
                # This can be expanded with more sophisticated analysis
                if guard_param in condition.vars_read:
                    return True

    return False

def __is_op_in_insn(insn, op):
    operands = insn.operands
    while operands:
        current_op = operands.pop(0)
        if compare_param(current_op,op):
            return True
        operands.extend(current_op.operands)
    return False

def is_ret_val_checked(bv: BinaryView, call_insn: HighLevelILInstruction):
    # TODO must make example code
    parent = call_insn.parent
    while parent:
        if parent.operation == HighLevelILOperation.HLIL_IF:
            return True
        if parent.operation in [HighLevelILOperation.HLIL_ASSIGN, HighLevelILOperation.HLIL_VAR_INIT, HighLevelILOperation.HLIL_ASSIGN_UNPACK]:
            break
        if parent.operation == HighLevelILOperation.HLIL_BLOCK:
            return False
        parent = parent.parent
    # parent holds the assignment operation here
    last_inst = list(bv.instructions)[call_insn.il_basic_block.end - 1]
    if last_inst.operation == HighLevelILOperation.HLIL_IF and __is_op_in_insn(last_inst,parent):
        return True

    return False

case_list = {
    "OS Command Injection": {**dict.fromkeys([
            "system",
            "_system",
            "_popen",
            "popen",
            "wpopen",
            "_wpopen",
            "execl",
            "execlp",
            "execle",
            "execv",
            "execvp",
            "execvpe",
            "_execl",
            "_execlp",
            "_execle",
            "_execv",
            "_execvp",
            "_execvpe"
        ],
            {
                "not_constant": {
                    0: {
                        "guard_check": no_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False
            }
        )
    },
    "Buffer Overflow":{
         **dict.fromkeys([
            "memmove",
            "_memmove",
            "wmemmove",
            "_wmemmove",
            "memcpy",
            "_memcpy",
            "wmemcpy",
            "_wmemcpy"

        ],
            {
                "not_constant": {
                    2: {
                        "guard_check": has_length_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False
            }
        ),
        **dict.fromkeys([
            "strncpy",
            "_strncpy",
            "lstrcpynA",
            "lstrcpynW",
            "strncat",
            "_strncat"
        ],
            {
                "not_constant": {
                    1: {
                        "guard_check": has_func_guard,
                        "guard_params": ["strlen"],
                        "multi_parameter": False,
                    },
                    2: {
                        "guard_check": has_length_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False
            }
        ),
        **dict.fromkeys([
            "strcpy",
            "_strcpy",
            "wcscpy",
            "_wcscpy",
            "_mbscpy",
            "mbscpy",
            "lstrcpyA",
            "lstrcpyW",
            "strcat",
            "_strcat",
            "wcscat",
            "_wcscat",
            "_mbscat",
            "mbscat",
            "lstrcatA",
            "lstrcatW"
        ],
            {
                "not_constant": {
                    1: {
                        "guard_check": has_func_guard,
                        "guard_params": ["strlen"],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False

            }
        ), 
        **dict.fromkeys([
            "sprintf",
            "_sprintf",
            "siprintf",
            "_siprintf"
        ],
            {
                "not_constant": {
                    2: {
                        "guard_check": has_func_guard,
                        "guard_params": ["strlen"],
                        "multi_parameter": True
                    }
                },
                "conditions": "param[1].operation == HighLevelILOperation.HLIL_CONST_PTR and '%s' in param[1].string[0]",
                "ret_val_check": False
            }
        )
    },
    "Format String Issue": {
        **dict.fromkeys([
            "_printf",
            "printf",
            "printk",
            "_printk",
            "vprintf",
            "_vprintf",
            "scanf",
            "_scanf",
            "vscanf",
            "_vscanf",
            "NSLog",
            "_NSLog",
            "wprintf",
            "_wprintf",
            "vwprintf",
            "_vwprintf",
            "vwscanf",
            "_vwscanf",
            "vscanf_s",
            "_vscanf_s",
            "vwscanf_s",
            "_vwscanf_s",
            "_vscprintf",
            "vscprintf",
            "_vscprintf_l",
            "vscprintf_l",
            "_vscwprintf",
            "vscwprintf",
            "_vscwprintf_l",
            "vscwprintf_l",
            "_vscprintf_p",
            "vscprintf_p",
            "_vscprintf_p_l",
            "vscprintf_p_l",
            "_vscwprintf_p",
            "vscwprintf_p",
            "_vscwprintf_p_l",
            "vscwprintf_p_l",
            "_vcprintf",
            "vcprintf",
            "_vcprintf_l",
            "vcprintf_l",
            "_vcwprintf",
            "vcwprintf",
            "_vcwprintf_l",
            "vcwprintf_l",
            "_vcprintf_p",
            "vcprintf_p",
            "_vcprintf_p_l",
            "vcprintf_p_l",
            "_vcwprintf_p",
            "vcwprintf_p",
            "_vcwprintf_p_l",
            "vcwprintf_p_l",
            "_vcwprintf_s",
            "vcwprintf_s",
            "_vcwprintf_s_l",
            "vcwprintf_s_l",
            "_vprintf_l",
            "vprintf_l",
            "_vwprintf_l",
            "vwprintf_l",
            "_vprintf_p",
            "vprintf_p",
            "_vprintf_p_l",
            "vprintf_p_l",
            "_vwprintf_p",
            "vwprintf_p",
            "_vwprintf_p_l",
            "vwprintf_p_l",
            "vprintf_s",
            "_vprintf_s",
            "_vprintf_s_l",
            "vprintf_s_l",
            "vwprintf_s",
            "_vwprintf_s",
            "_vwprintf_s_l",
            "vwprintf_s_l"
        ],
            {
                "not_constant": {
                    0: {
                        "guard_check": no_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False

            }
        ),
        **dict.fromkeys([
            "wsprintf",
            "_wsprintf",
            "wsprintfW",
            "_wsprintfW",
            "wsprintfW@IAT",
            "_wsprintfW@IAT",
            "wsprintfA",
            "_wsprintfA",
            "wsprintfA@IAT",
            "_wsprintfA@IAT",
            "fprintf",
            "_fprintf",
            "sprintf",
            "_sprintf",
            "vsprintf",
            "_vsprintf",
            "vfprintf",
            "_vfprintf",
            "sscanf",
            "_sscanf",
            "fscanf",
            "_fscanf",
            "vsscanf",
            "_vsscanf",
            "vfscanf",
            "_vfscanf",
            "fwprintf",
            "_fwprintf",
            "vfwprintf",
            "_vfwprintf",
            "_vfprintf_l",
            "vfprintf_l",
            "_vfwprintf_l",
            "vfwprintf_l",
            "_vfprintf_p",
            "asprintf",
            "_asprintf",
            "vfprintf_p",
            "_vfprintf_p_l",
            "vfprintf_p_l",
            "_vfwprintf_p",
            "vfwprintf_p",
            "_vfwprintf_p_l",
            "vfwprintf_p_l",
            "vfprintf_s",
            "_vfprintf_s",
            "_vfprintf_s_l",
            "vfprintf_s_l",
            "vfwprintf_s",
            "_vfwprintf_s",
            "_vfwprintf_s_l",
            "vfwprintf_s_l",
            "vasprintf",
            "vasprintf",
            "vfwscanf",
            "_vfwscanf",
            "vfscanf_s",
            "_vfscanf_s",
            "vfwscanf_s",
            "_vfwscanf_s",
            "_vsprintf_l",
            "vsprintf_l",
            "__vswprintf_l",
            "vswprintf",
            "_vswprintf",
            "vsprintf_s",
            "_vsprintf_s",
            "vswprintf_s",
            "_vswprintf_s",
            "vswscanf",
            "_vswscanf",
            "vsscanf_s",
            "_vsscanf_s",
            "vswscanf_s",
            "_vswscanf_s",
            "__wprintf_chk",
            "___vprintf_chk",
            "__vwprintf_chk",
            "___printf_chk",
            "__printf_chk",
            "__vprintf_chk",
            "siprintf",
            "_siprintf"
        ],
            {
                "not_constant": {
                    1: {
                        "guard_check": no_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False

            }
        ),
        **dict.fromkeys([
            "vsnprintf",
            "_vsnprintf",
            "snprintf",
            "_snprintf",
            "vswprintf",
            "_vswprintf",
            "swprintf",
            "_swprintf",
            "_vsnprintf_l",
            "vsnprintf_l",
            "_vsnwprintf",
            "vsnwprintf",
            "_vsnwprintf_l",
            "vsnwprintf_l",
            "_vsnprintf_s",
            "vsnprintf_s",
            "_vsnwprintf_s",
            "vsnwprintf_s",
            "_vswprintf_l",
            "vswprintf_l",
            "_vsprintf_p",
            "vsprintf_p",
            "_vsprintf_p_l",
            "_sprintf_p_l",
            "_vswprintf_p",
            "vswprintf_p",
            "_vswprintf_p_l",
            "vswprintf_p_l",
            "vsprintf_s",
            "_vsprintf_s",
            "_vsprintf_s_l",
            "vsprintf_s_l",
            "vswprintf_s",
            "_vswprintf_s",
            "_vswprintf_s_l",
            "vswprintf_s_l",
            "__asprintf_chk",
            "__dprintf_chk",
            "___fprintf_chk",
            "__fprintf_chk",
            "__fwprintf_chk",
            "__obstack_vprintf_chk",
            "__obstack_printf_chk",
            "__vasprintf_chk",
            "__vdprintf_chk",
            "___vfprintf_chk",
            "__vfwprintf_chk",
            "__vfprintf_chk"
        ],
            {
                "not_constant": {
                    2: {
                        "guard_check": no_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False

            }
        ),
        **dict.fromkeys([
            "vsnprintf_s",
            "_vsnprintf_s",
            "_vsnprintf_s_l",
            "vsnprintf_s_l",
            "_vsnwprintf_s",
            "vsnwprintf_s",
            "_vsnwprintf_s_l",
            "vsnwprintf_s_l",
            "___vsprintf_chk",
            "___sprintf_chk",
            "__sprintf_chk",
            "__vsprintf_chk"
        ],
            {
                "not_constant": {
                    3: {
                        "guard_check": no_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False

            }
        ),
        **dict.fromkeys([
            "___snprintf_chk",
            "__snprintf_chk",
            "__swprintf_chk",
            "___vsnprintf_chk",
            "__vswprintf_chk",
            "__vsnprintf_chk"
        ],
            {
                "not_constant": {
                    4: {
                        "guard_check": no_guard,
                        "guard_params": [],
                        "multi_parameter": False
                    }
                },
                "conditions": "True",
                "ret_val_check": False

            }
        ),
    },
    "Unchecked Return Value of 'scanf'": {
        **dict.fromkeys([
            "_fscanf",
            "_scanf",
            "_sscanf",
            "_vfscanf",
            "_vfscanf_s",
            "_vfwscanf",
            "_vfwscanf_s",
            "_vscanf",
            "__isoc99_scanf",
            "_vscanf_s",
            "_vsscanf",
            "_vsscanf_s",
            "_vswscanf",
            "_vswscanf_s",
            "_vwscanf",
            "_vwscanf_s",
            "fscanf",
            "scanf",
            "sscanf",
            "vfscanf",
            "vfscanf_s",
            "vfwscanf",
            "vfwscanf_s",
            "vscanf",
            "vscanf_s",
            "vsscanf",
            "vsscanf_s",
            "vswscanf",
            "vswscanf_s",
            "vwscanf",
            "vwscanf_s"
        ],
            {
                "not_constant": {
                },
                "conditions": "param[1].operation == HighLevelILOperation.HLIL_CONST_PTR and '%s' in param[1].string[0]",
                "ret_val_check": False
            }
        ),
    }
}


with open_index(bv, 'Potential Security Issues') as index:
    f_count = 1
    for func in bv.functions:
        notify_progress(f_count, len(bv.functions), 'Finding potential security issues...')
        f_count += 1
        try:
            hlil = func.hlil
        except exceptions.ILException:
            #log_warn(f"HLIL not available for function at {func.name}")
            continue
        for block in func.hlil:
            for insn in block:
                if insn.operation == HighLevelILOperation.HLIL_CALL:
                    for case in case_list:
                        if str(insn.dest) in case_list[case]:
                            details = case_list[case][str(insn.dest)]
                            mark = None
                            for n_c in details["not_constant"]:
                                if is_parameter_dynamic(insn,n_c,details["not_constant"][n_c]["multi_parameter"]) and conditions(bv,details["conditions"],insn.params):
                                    # Not a constant, move on
                                    if details["not_constant"][n_c]["guard_check"](bv,insn,n_c,details["not_constant"][n_c]["guard_params"],details["not_constant"][n_c]["multi_parameter"]):
                                        mark = "Low"
                                    else:
                                        mark = "High"
                                elif mark:
                                    if mark == "High":
                                        mark = "Low"
                                    else:
                                        mark = "Info"
                            if details["ret_val_check"]:
                                # Do a check for a return value
                                is_ret_val_checked(bv,insn)
                            if mark:
                                index.add_entry(insn, {"Description": case ,"Priority": mark, "Found At": insn.function.source_function.name})

