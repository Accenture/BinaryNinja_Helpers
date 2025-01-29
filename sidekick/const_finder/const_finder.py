
"""Indexer to find specified constants in HLIL"""
from binaryninja import *



ASSIGNMENTS = [HighLevelILOperation.HLIL_ASSIGN, HighLevelILOperation.HLIL_VAR_INIT]
CALLS = [HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL]
INT_COMPARE = [HighLevelILOperation.HLIL_CMP_E,HighLevelILOperation.HLIL_CMP_NE,HighLevelILOperation.HLIL_CMP_SLT,HighLevelILOperation.HLIL_CMP_ULT,HighLevelILOperation.HLIL_CMP_SLE,HighLevelILOperation.HLIL_CMP_ULE,HighLevelILOperation.HLIL_CMP_SGE,HighLevelILOperation.HLIL_CMP_UGE,HighLevelILOperation.HLIL_CMP_SGT,HighLevelILOperation.HLIL_CMP_UGT]
FLOAT_COMPARE = [HighLevelILOperation.HLIL_FCMP_E,HighLevelILOperation.HLIL_FCMP_NE,HighLevelILOperation.HLIL_FCMP_LT,HighLevelILOperation.HLIL_FCMP_LE,HighLevelILOperation.HLIL_FCMP_GE,HighLevelILOperation.HLIL_FCMP_GT,HighLevelILOperation.HLIL_FCMP_O,HighLevelILOperation.HLIL_FCMP_UO]
MATH = [HighLevelILOperation.HLIL_ADD, HighLevelILOperation.HLIL_ADC, HighLevelILOperation.HLIL_SUB, HighLevelILOperation.HLIL_SBB, HighLevelILOperation.HLIL_AND, HighLevelILOperation.HLIL_OR, HighLevelILOperation.HLIL_XOR, HighLevelILOperation.HLIL_LSL, HighLevelILOperation.HLIL_LSR,HighLevelILOperation.HLIL_ASR,HighLevelILOperation.HLIL_ROL,HighLevelILOperation.HLIL_RLC,HighLevelILOperation.HLIL_ROR, HighLevelILOperation.HLIL_RRC,HighLevelILOperation.HLIL_MUL,HighLevelILOperation.HLIL_MULU_DP,HighLevelILOperation.HLIL_MULS_DP,HighLevelILOperation.HLIL_DIVU,HighLevelILOperation.HLIL_DIVU_DP,HighLevelILOperation.HLIL_DIVS,HighLevelILOperation.HLIL_DIVS_DP,HighLevelILOperation.HLIL_MODU,HighLevelILOperation.HLIL_MODU_DP,HighLevelILOperation.HLIL_MODS,HighLevelILOperation.HLIL_MODS_DP,HighLevelILOperation.HLIL_NEG,HighLevelILOperation.HLIL_NOT]
FLOAT_MATH = [HighLevelILOperation.HLIL_FADD,HighLevelILOperation.HLIL_FSUB,HighLevelILOperation.HLIL_FMUL,HighLevelILOperation.HLIL_FDIV,HighLevelILOperation.HLIL_FSQRT,HighLevelILOperation.HLIL_FNEG,HighLevelILOperation.HLIL_FABS]
ARRAY_INDEX = [HighLevelILOperation.HLIL_ARRAY_INDEX]
RETURN = [HighLevelILOperation.HLIL_RET]
ANY = list(HighLevelILOperation)


def has_parent_with_op(insn, ops):
    current_parent = insn.parent
    while current_parent.operation != HighLevelILOperation.HLIL_BLOCK:
        if current_parent.operation in ops:
            return True
        else:
            current_parent = current_parent.parent

def contains(insn,const_val,parent_ops,direct_only,verbose=False):
    ops = insn.operands
    while ops:
        op = ops.pop(0)
        if type(op) is list:
            ops.extend(op)
            continue
        try:
            if op.operation in [HighLevelILOperation.HLIL_CONST, HighLevelILOperation.HLIL_FLOAT_CONST] and op.value.value == const_val:
                if direct_only:
                    if op.parent.operation in parent_ops:
                        return True
                else:
                    if has_parent_with_op(op,parent_ops):
                        return True
            else:
                ops.extend(op.operands)
        except:
            pass

    return False


def check_constant_use(insn, constant, type_of_use,direct_only):
    #if insn.operation in type_of_use:
    return contains(insn, constant,type_of_use,direct_only)
    #return False

def find_constants_in_function(func, constants):
    found_constants = set()
    for block in func.hlil.basic_blocks:
        for insn in block:
            for const, details in constants.items():
                if check_constant_use(insn, const, details["type_of_use"],details["direct_use_only"]):
                    found_constants.add(hex(const))
    return found_constants

mtf = interaction.MultilineTextField("Provide dictionary with constants:")
tlf = interaction.TextLineField("Name of the index:")
if interaction.get_form_input([tlf,mtf],"Const Finder"):
    constants_to_look_for = eval(mtf.result)
    if tlf.result:
        index_name = tlf.result
    else:
        index_name = "Constant Finder"
    with open_index(bv, index_name) as index:
        try:
            results = {}
            f_count = 1
            for func in bv.functions:
                notify_progress(f_count, len(bv.functions), 'Checking for interesting constants ...')
                f_count += 1
                for name, constants in constants_to_look_for.items():
                    try:
                        hlil = func.hlil
                    except exceptions.ILException:
                        #log_warn(f"HLIL not available for function at {func.name}")
                        continue
                    found = find_constants_in_function(func, constants)
                    if found:
                        if len(found) == len(constants):
                            if func not in results:
                                results[func] = {"matches": {name: list(found)}}
                            else:
                                results[func]["matches"][name] = list(found)
            for func, result in results.items():
                str_match = ""
                for m in result["matches"]:
                    str_match += f"{m}, "
                str_match = str_match[:-2]
                index.add_entry(func, {"Contains": str_match})
        except Exception as e:
            log_error(f"Error in indexer: {str(e)}")
