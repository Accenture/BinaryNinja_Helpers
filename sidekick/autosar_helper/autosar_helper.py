from binaryninja import *
import json
import requests

MODULE_ID_INDEX = 0
SERVICE_ID_INDEX = 2


# Try to find the call to the
# Std_ReturnType Det_ReportError (
#   uint16 ModuleId,
#   uint8 InstanceId,
#   uint8 ApiId,
#   uint8 ErrorId
# )
# Check up to 10 XREFs of function to see if it is called with valid combination of module_id and service_id values.
# If it does mark it as potential call and notify user, wait for manual confirmation.
# Once manually confimred rename all functions based on the the data in autosar_functions.

class PopulateASClassicTypes():
    def __init__(self,bv):
        self.bv = bv

    def populate_types(self):
        try:
            result = requests.get("http://127.0.0.1:8000/autosar.h")
            if result.status_code == 200:
                tps = self.bv.platform.parse_types_from_source(result.text)
                self.bv.define_user_types([(x,tps.types[x]) for x in tps.types],self.echo_progress)
                return
        except:
            pass
        autosar_types_path = interaction.get_open_filename_input("Select file with AUTOSAR types:")
        if not autosar_types_path:
            print("No file selected. No action.")
        else:
            print(f"[AUTOSAR Helper] Applying types from {autosar_types_path}")
            tps = self.bv.platform.parse_types_from_source_file(autosar_types_path)
            self.bv.define_user_types([(x,tps.types[x]) for x in tps.types],self.echo_progress)

    def start(self):
        self.populate_types()

    def echo_progress(self,c,t):
        #print(f"{c}/{t}")
        self.progress = f"AutoSAR Helper applying types ...  ({c}/{t})"

class MarkErrorHandlingFunc():
    def __init__(self, bv, current_address):
        self.bv = bv
        self.current_address = current_address
        self.autosar_functions = None


        if bv.arch.name == "tricore":
            self.det_error_type = "unsigned char Det_ReportError(unsigned short ModuleId @ d4, unsigned char InstanceId @ d5, unsigned char ApiId @d6, unsigned char ErrorId @d7)"
        else:
            self.det_error_type = "unsigned char Det_ReportError(unsigned short ModuleId, unsigned char InstanceId, unsigned char ApiId, unsigned char ErrorId)"


    # Returns the details of the function
    def match_params(self,call_params):
        if len(call_params) > SERVICE_ID_INDEX:
            if call_params[MODULE_ID_INDEX].operation == HighLevelILOperation.HLIL_CONST and call_params[SERVICE_ID_INDEX].operation == HighLevelILOperation.HLIL_CONST:
                # Two constants are passed, move on
                try:
                    return self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]
                except KeyError:
                    return None
        return None


    def get_call_params(self,func,call_insn):
        try:
            if call_insn.operation in [HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL] and call_insn.dest.value.value == func.start:
                # This is already correct call
                return call_insn.params
            ops = call_insn.operands
            while ops:
                current_op = ops.pop(0)
                if type(current_op) is list:
                    ops.extend(current_op)
                    continue
                if current_op.operation in [HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL] and current_op.dest.value.value == func.start:
                    return current_op.params
                else:
                    ops.extend(current_op.operands)
        except:
            pass
        return None

    def start(self):
        try:
            result = requests.get("http://127.0.0.1:8000/autosar.json",timeout=2)
            if result.status_code == 200:
                self.autosar_functions = json.loads(result.text)
                self.rename_functions()
                return
        except:
            print("Error retrieving the AUTOSAR metadata from online source!")
        try:
            self.autosar_functions = json.load(open(interaction.get_open_filename_input("Select file with AUTOSAR metadata:"),"r"))
            self.rename_functions()
        except:
            print("No file was selected. Aborting operation")


    def find_call_insn(self,call_insn,func_name):
        func_to_scan = self.bv.get_functions_containing(call_insn.address)[0]
        for instruction in func_to_scan.hlil.instructions:
            if func_name in str(instruction):
                return instruction

    def rename_functions(self):
        f_count = 1
        current_func = self.bv.get_functions_containing(self.current_address)[0]
        current_func.set_user_type(self.det_error_type)
        current_func.name = "Det_ReportError"
        current_func.mark_caller_updates_required()
        current_func.reanalyze()
        while self.bv.analysis_progress.state != 2:
            pass
        caller_sites = list(current_func.caller_sites)
        for call_insn in caller_sites:
            notify_progress(f_count, len(caller_sites), 'Renaming functions ...')
            f_count += 1
            try:
                if call_insn.hlil:
                    call_params = self.get_call_params(current_func,call_insn.hlil)
                else:
                    call_params = self.get_call_params(current_func,self.find_call_insn(call_insn,"Det_ReportError"))
            except (exceptions.ILException, AssertionError, IndexError):
                print(f"[AUTOSAR Helper] Got IL Excpetion for {hex(call_insn.address)}. You may want to force the analysis for this function.")
                continue
            if call_params:
                if str(call_params[MODULE_ID_INDEX].value.value) in self.autosar_functions:
                    # Module exists
                    module = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]
                    if str(call_params[SERVICE_ID_INDEX].value.value) in module["functions"]:
                        # Function exists
                        func_to_rename = self.bv.get_functions_containing(call_insn.address)[0]
                        func_to_rename.name = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]['name']
                        func_to_rename.comment = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]['comments']
                    else:
                        for func_to_rename in self.bv.get_functions_containing(call_insn.address):
                            func_to_rename.name = f"{self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]['short_name']}_func_{hex(call_params[SERVICE_ID_INDEX].value.value)}"
                            func_to_rename.comment = f"Part of the {self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]['name']} module"
                else:
                    for func_to_rename in self.bv.get_functions_containing(call_insn.address):
                        func_to_rename.name = f"ComplexDriver_func_{hex(call_params[SERVICE_ID_INDEX].value.value)}"




class AutoFindErrorHandling():
    def __init__(self, bv):
        self.bv = bv
        self.current_top = None
        self.autosar_functions = None
        #self.filename = "autosar.json"
        if bv.arch.name == "tricore":
            self.det_error_type = "unsigned char Det_ReportError(unsigned short ModuleId @ d4, unsigned char InstanceId @ d5, unsigned char ApiId @d6, unsigned char ErrorId @d7)"
        else:
            self.det_error_type = "unsigned char Det_ReportError(unsigned short ModuleId, unsigned char InstanceId, unsigned char ApiId, unsigned char ErrorId)"


    def are_params_const(self,call_params):
        if len(call_params) > SERVICE_ID_INDEX:
            if call_params[MODULE_ID_INDEX].operation == HighLevelILOperation.HLIL_CONST and call_params[SERVICE_ID_INDEX].operation == HighLevelILOperation.HLIL_CONST:
                return 1
        return 0

    # Returns the details of the function
    def match_params(self,call_params):
        if len(call_params) > SERVICE_ID_INDEX:
            if call_params[MODULE_ID_INDEX].operation == HighLevelILOperation.HLIL_CONST and call_params[SERVICE_ID_INDEX].operation == HighLevelILOperation.HLIL_CONST:
                # Two constants are passed, move on
                try:
                    return self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]
                except KeyError:
                    return None
        return None


    def get_call_params(self,func,call_insn):
        try:
            if call_insn.operation in [HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL] and call_insn.dest.value.value == func.start:
                # This is already correct call
                return call_insn.params
            ops = call_insn.operands
            while ops:
                current_op = ops.pop(0)
                if type(current_op) is list:
                    ops.extend(current_op)
                    continue
                if current_op.operation in [HighLevelILOperation.HLIL_CALL, HighLevelILOperation.HLIL_TAILCALL] and current_op.dest.value.value == func.start:
                    return current_op.params
                else:
                    ops.extend(current_op.operands)
        except:
            pass
        return None

    def start(self):
        try:
            result = requests.get("http://127.0.0.1:8000/autosar.json",timeout=2)
            if result.status_code == 200:
                self.autosar_functions = json.loads(result.text)
                rename = self.find_det_error_function()
                if self.current_top and rename:
                    self.rename_functions()
                return
        except:
            print("Error retrieving the AUTOSAR metadata from online source!")
        try:
            self.autosar_functions = json.load(open(interaction.get_open_filename_input("Select file with AUTOSAR metadata:"),"r"))
            rename = self.find_det_error_function()
            if self.current_top and rename:
                self.rename_functions()
        except:
            print("No file was selected. Aborting operation")


    def find_det_error_function(self):
        f_count = 1
        previous_type = None
        SKIP_TRESHOLD = 50
        print(SKIP_TRESHOLD)
        for func in self.bv.functions:
            notify_progress(f_count, len(bv.functions), 'Trying to find the AUTOSAR error handling functions ...')
            f_count += 1
            # SKIP IF THERE ARE NOT THAT MANY XREFS
            if len(list(func.caller_sites)) < SKIP_TRESHOLD:
                continue

            matches = {}
            if len(func.parameter_vars.vars) == 0:
                # Previous type
                print(f"CHANGING TYPE OF FUNC: {func.name}")
                previous_type = func.type

                func.set_user_type(self.det_error_type)
                func.mark_caller_updates_required()
                func.reanalyze()
                while self.bv.analysis_progress.state != 2:
                    pass
            else:
                previous_type = func.type
            const_params_counter = 0
            for call_insn in func.caller_sites:
                # Dig the actual call from the insn and get parameters
                try:
                    if call_insn.hlil:
                        call_params = self.get_call_params(func,call_insn.hlil)
                    else:
                        call_params = self.get_call_params(func,self.find_call_insn(call_insn,func.name))
                    if call_params:
                        const_params_counter += self.are_params_const(call_params)
                        matched_func = self.match_params(call_params)
                        if matched_func:
                            #matches.append({"match_insn":call_insn.address, "matched_func":matched_func})
                            matches[call_insn.address] = {"matched_func":matched_func, "call_params": call_params.copy()}
                except (exceptions.ILException, AssertionError, IndexError):
                    print(f"[AUTOSAR Helper] Got IL Excpetion for {hex(call_insn.address)}. You may want to force the analysis for this function.")
            if not self.current_top:
                self.current_top = {"function": func, "matches": matches.copy(), "previous_type": previous_type, "const_param_ratio": const_params_counter/len(list(func.caller_sites)),"matches_ratio": len(matches)/len(list(func.caller_sites))}
            elif len(matches) > len(self.current_top["matches"]):
                # Restore previosu func type
                print(f"[AUTOSAR Helper] GOT NEW TOP {len(matches)} vs {len(self.current_top['matches'])}")
                self.current_top["function"].type = self.current_top["previous_type"]
                self.current_top["function"].mark_caller_updates_required()
                self.current_top['function'].reanalyze()

                # Now replace the old one
                self.current_top = {"function": func, "matches": matches.copy(), "previous_type": previous_type,"const_param_ratio": const_params_counter/len(list(func.caller_sites)),"matches_ratio": len(matches)/len(list(func.caller_sites))}
            else:
                func.type = previous_type
        if not self.current_top or not self.current_top['matches'] or len(self.current_top['matches']) < 10 or (int(((self.current_top['const_param_ratio'] * 2 + self.current_top['matches_ratio'])/3) * 100) < 40):
            self.current_top = None
            print("Failed to identify the error handling function!")
            return False
        if interaction.show_message_box("Function identified",f"It seems that function {self.current_top['function'].name} can be a 'Det_ReportError' function ({int(((self.current_top['const_param_ratio'] * 2 + self.current_top['matches_ratio'])/3) * 100)}% probability). Do you want to proceed with automatic function renaming?",MessageBoxButtonSet.YesNoButtonSet) == 1:
            print(f"[AUTOSAR Helper] Found the best matching error handling function: {self.current_top['function'].name} with {len(self.current_top['matches'])} matches. Renaming it to 'Det_ReportError'.")
            self.current_top['function'].name = "Det_ReportError"
            return True
        else:
            self.current_top["function"].type = self.current_top["previous_type"]
            self.current_top["function"].mark_caller_updates_required()
            self.current_top['function'].reanalyze()
            return False

    def find_call_insn(self,call_insn,func_name):
        func_to_scan = self.bv.get_functions_containing(call_insn.address)[0]
        for instruction in func_to_scan.hlil.instructions:
            if func_name in str(instruction):
                return instruction

    def rename_functions(self):
        f_count = 1
        caller_sites = list(self.current_top["function"].caller_sites)
        for call_insn in caller_sites:
            notify_progress(f_count, len(caller_sites), 'Renaming functions ...')
            f_count += 1
            if call_insn.address not in self.current_top["matches"].keys():
                try:
                    if call_insn.hlil:
                        call_params = self.get_call_params(self.current_top["function"],call_insn.hlil)
                    else:
                        call_params = self.get_call_params(self.current_top["function"],self.find_call_insn(call_insn,"Det_ReportError"))
                except (exceptions.ILException, IndexError):
                    print(f"[AUTOSAR Helper] FAILED HERE FOR CALL AT {hex(call_insn.address)}")
                if call_params:
                    try:
                        # unkown reference should be marked based on module number
                        for func_to_rename in self.bv.get_functions_containing(call_insn.address):
                            func_to_rename.name = f"{self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]['short_name']}_func_{hex(call_params[SERVICE_ID_INDEX].value.value)}"
                            func_to_rename.comment = f"Part of the {self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]['name']} module"
                        #print(f"{hex(func_to_rename.start)}: {self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]['short_name']}_func_{hex(call_params[SERVICE_ID_INDEX].value.value)}")
                    except KeyError:
                        for func_to_rename in self.bv.get_functions_containing(call_insn.address):
                            func_to_rename.name = f"ComplexDriver_func_{hex(call_params[SERVICE_ID_INDEX].value.value)}"
                    except IndexError:
                        print(f"[AUTOSAR Helper] FAILED FOR CALL AT {hex(call_insn.address)}")

                else:
                    print(f"[AUTOSAR Helper] NO PARAMS FOR {hex(call_insn.address)} = {call_params}")
            else:
                func_to_rename = self.bv.get_functions_containing(call_insn.address)[0]
                func_to_rename.name = self.current_top["matches"][call_insn.address]['matched_func']['name']
                func_to_rename.comment = self.current_top["matches"][call_insn.address]['matched_func']['comments']
                try:
                    func_to_rename.set_user_type(self.current_top["matches"][call_insn.address]['matched_func']['type'])
                except:
                    print(f"[AUTOSAR Helper] FAILED TO APPLY TYPE FOR: {func_to_rename.name} at {hex(func_to_rename.start)} ({self.current_top['matches'][call_insn.address]['matched_func']['type']})")



#if interaction.show_message_box("Load AUTOSAR types?",f"Would you like to add AUTOSAR Classic types?",MessageBoxButtonSet.YesNoButtonSet) == 1:
#
match interaction.get_choice_input("What should I do?", "AUTOSAR Helper", ["Load AUTOSAR Types", "Scan for error handling", "Set current function as 'Det_ReportError'"]):
    case 0:
        print("[AUTOSAR Helper] Loading AUTOSAR types - START")
        type_helper = PopulateASClassicTypes(bv)
        type_helper.start()
        print("[AUTOSAR Helper] Loading AUTOSAR types - DONE")
    case 1:
        print("[AUTOSAR Helper] Scanning for AUTOSAR error handling - START")
        rename_helper = AutoFindErrorHandling(bv)
        rename_helper.start()
        print("[AUTOSAR Helper] Scanning for AUTOSAR error handling - DONE")
    case 2:
        print(f"[AUTOSAR Helper] [AUTOSAR Helper] Setting function at {hex(current_function.start)} as 'Det_ReportError' - START")
        rename_helper = MarkErrorHandlingFunc(bv,current_function.start)
        rename_helper.start()
        print(f"[AUTOSAR Helper] [AUTOSAR Helper] Setting function at {hex(current_function.start)} as 'Det_ReportError' - DONE")
    case _:
        print("[AUTOSAR Helper] No choice selected.")
