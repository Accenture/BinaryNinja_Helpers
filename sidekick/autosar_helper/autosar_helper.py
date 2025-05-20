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
            result = requests.get("https://raw.githubusercontent.com/Accenture/BinaryNinja_Helpers/refs/heads/main/sidekick/autosar_helper/autosar.h")
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
            result = requests.get("https://raw.githubusercontent.com/Accenture/BinaryNinja_Helpers/refs/heads/main/sidekick/autosar_helper/autosar.json",timeout=2)
            if result.status_code == 200:
                self.autosar_functions = json.loads(result.text)
                self.rename_functions()
                return
        except Exception as e:
            print(e)
            print("Error retrieving the AUTOSAR metadata from online source!")
        try:
            self.autosar_functions = json.load(open(interaction.get_open_filename_input("Select file with AUTOSAR metadata:"),"r"))
            self.rename_functions()
        except:
            print("No file was selected. Aborting operation")


    def find_call_insn(self,call_insn,func_name):
        func_to_scan = self.bv.get_functions_containing(call_insn.address)[0]
        if func_to_scan.hlil:
            for instruction in func_to_scan.hlil.instructions:
                if func_name in str(instruction):
                    return instruction

    def rename_functions(self):
        f_count = 1
        current_function.set_user_type(self.det_error_type)
        current_function.name = "Det_ReportError"
        current_function.mark_caller_updates_required()
        current_function.reanalyze()
        while self.bv.analysis_progress.state != 2:
            pass
        caller_sites = list(current_function.caller_sites)
        for call_insn in caller_sites:
            notify_progress(f_count, len(caller_sites), 'Renaming functions ...')
            f_count += 1
            try:
                if call_insn.hlil:
                    call_params = self.get_call_params(current_function,call_insn.hlil)
                else:
                    call_params = self.get_call_params(current_function,self.find_call_insn(call_insn,"Det_ReportError"))
            except (exceptions.ILException, AssertionError, IndexError):
                log_warn(f"[AUTOSAR Helper] Got IL Exception for {hex(call_insn.address)}. You may want to force the analysis for this function.")
            except Exception as e:
                print(f"Unexpected error: {e}")
            if call_params:
                if str(call_params[MODULE_ID_INDEX].value.value) in self.autosar_functions:
                    # Module exists
                    module = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]
                    if str(call_params[SERVICE_ID_INDEX].value.value) in module["functions"]:
                        # Function exists
                        func_to_rename = self.bv.get_functions_containing(call_insn.address)[0]
                        func_to_rename.name = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]['name']
                        func_to_rename.comment = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]['comments']
                        try:
                            func_to_rename.set_user_type(self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]['type'])
                        except:
                            afuncs = self.autosar_functions[str(call_params[MODULE_ID_INDEX].value.value)]["functions"][str(call_params[SERVICE_ID_INDEX].value.value)]['type']
                            print(f"[AUTOSAR Helper] FAILED TO APPLY TYPE FOR: {func_to_rename.name} at {hex(func_to_rename.start)} ({afuncs})")
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
            result = requests.get("https://raw.githubusercontent.com/Accenture/BinaryNinja_Helpers/refs/heads/main/sidekick/autosar_helper/autosar.json",timeout=2)
            if result.status_code == 200:
                self.autosar_functions = json.loads(result.text)
                rename = self.find_det_error_function()
                if self.current_top and rename:
                    self.rename_functions()
                return
        except Exception as e:
            print(e)
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
                    log_warn(f"[AUTOSAR Helper] Got IL Exception for {hex(call_insn.address)}. You may want to force the analysis for this function.")
            if not self.current_top:
                self.current_top = {"function": func, "matches": matches.copy(), "previous_type": previous_type, "const_param_ratio": const_params_counter/len(list(func.caller_sites)),"matches_ratio": len(matches)/len(list(func.caller_sites))}
            elif len(matches) > len(self.current_top["matches"]):
                # Restore previosu func type
                print(f"[AUTOSAR Helper] Got potential candiate ({func.name}) with {len(matches)} vs. {len(self.current_top['matches'])}")
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
        if func_to_scan.hlil:
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


class MarkReadWriteFuncs:
    def __init__(self,bv):
        self.bv = bv
        self.func_list = [
            "Adc_ReadGroup",
            "BndM_WriteBlock_BlockId_Shortname",
            "Xxx_BndMWriteStartFinish",
            "Xxx_BndMWriteBlockFinish",
            "Xxx_BndMWriteFinalizeFinish",
            "Can_Write",
            "CanIf_ReadRxPduData",
            "CanIf_ReadTxNotifStatus",
            "CanIf_ReadRxNotifStatus",
            "CanTrcv_ReadTrcvTimeoutFlag",
            "CanTrcv_ReadTrcvSilenceFlag",
            "CanTp_ReadParameter",
            "CanXL_Write",
            "ComM_ReadInhibitCounter",
            "Crypto_vi_ai_NvBlock_ReadFrom_NvBlock",
            "Crypto_vi_ai_NvBlock_WriteTo_NvBlock",
            "Dcm_BndMWriteBlockFinish",
            "Xxx_ReadDidData",
            "Dcm_ProcessTransferDataRead",
            "Dcm_ProcessTransferDataWrite",
            "Xxx_ReadData",
            "Xxx_ReadData",
            "Xxx_ReadData",
            "Xxx_ReadData",
            "Xxx_WriteData",
            "Xxx_WriteData",
            "Xxx_WriteData",
            "Xxx_WriteData",
            "Xxx_WriteDidData",
            "Xxx_ReadDidRangeDataLength",
            "Dem_DcmReadDataOfPID01",
            "Dem_DcmReadDataOfPID1C",
            "Dem_DcmReadDataOfPID21",
            "Dem_DcmReadDataOfPID30",
            "Dem_DcmReadDataOfPID31",
            "Dem_DcmReadDataOfPID41",
            "Dem_DcmReadDataOfPID4D",
            "Dem_DcmReadDataOfPID4E",
            "Dem_DcmReadDataOfPID91",
            "Dem_DcmReadDataOfOBDFreezeFrame",
            "Dem_DcmReadDataOfPIDF501",
            "Dem_J1939DcmReadDiagnosticReadiness1",
            "Dem_J1939DcmReadDiagnosticReadiness2",
            "Dem_J1939DcmReadDiagnosticReadiness3",
            "Dem_ReadDataOfPID01",
            "Ea_Read",
            "Ea_Write",
            "Eep_Read",
            "Eep_Write",
            "Eth_WriteMii",
            "Eth_ReadMii",
            "EthIf_WritePortMirrorConfiguration",
            "EthIf_ReadPortMirrorConfiguration",
            "EthSwt_ReadTrcvRegister",
            "EthSwt_WriteTrcvRegister",
            "EthSwt_WritePortMirrorConfiguration",
            "EthSwt_ReadPortMirrorConfiguration",
            "EthTrcv_ReadMiiIndication",
            "EthTrcv_WriteMiiIndication",
            "Fls_Write",
            "Fls_Read",
            "Fee_Read",
            "Fee_Write",
            "Fr_ReadCCConfig",
            "FrIf_ReadCCConfig",
            "MemIf_Read",
            "MemIf_Write",
            "MemAcc_Read",
            "MemAcc_Write",
            "Mem_Read",
            "Mem_Write",
            "NvM_ReadBlock",
            "NvM_WriteBlock",
            "NvM_ReadPRAMBlock",
            "NvM_WritePRAMBlock",
            "ReadPeripheral8",
            "ReadPeripheral16",
            "ReadPeripheral32",
            "WritePeripheral8",
            "WritePeripheral16",
            "WritePeripheral32",
            "IocWrite_IocId_SenderId",
            "IocWriteGroup_IocId",
            "IocRead_IocId_ReceiverId",
            "IocReadGroup_IocId",
            "SoAd_ReadDhcpHostNameOption",
            "SoAd_WriteDhcpHostNameOption",
            "SoAd_IsConnectionReady",
            "NvM_ReadPRAMBlock",
            "Xxx_ReadDataLength",
            "Xxx_ConditionCheckRead",
            "Rte_Rips_PlugIn_Read_SwcBswIPartition_ExE_CGI",
            "Rte_Rips_PlugIn_Write_SwcBswIPartition_ExE_CGI",
            "NvM_WritePRAMBlock",
            "Xxx_ReadDataLength",
            "Xxx_ReadData",
            "Xxx_WriteData",
            "Spi_WriteIB",
            "Spi_ReadIB",
            "TcpIp_DhcpReadOption",
            "TcpIp_DhcpV6ReadOption",
            "TcpIp_DhcpWriteOption",
            "TcpIp_DhcpV6WriteOption",
            "WEth_WriteTrcvRegs",
            "WEth_ReadTrcvRegs"
        ]

    def start(self):
        with open_index(bv, "AUTOSAR Functions to investigate (Read/Write operations)") as index:
            func_len = len(list(self.bv.functions))
            f_count = 0
            for func in self.bv.functions:
                notify_progress(f_count, func_len, 'Marking functions for investigation ...')
                if func.name in self.func_list:
                    index.add_entry(func, {})
                f_count += 1



#if interaction.show_message_box("Load AUTOSAR types?",f"Would you like to add AUTOSAR Classic types?",MessageBoxButtonSet.YesNoButtonSet) == 1:
#
match interaction.get_choice_input("What should I do?", "AUTOSAR Helper", ["Load AUTOSAR Types", "Scan for error handling", "Set current function as 'Det_ReportError'","Mark all Read/Write Functions"]):
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
        print(f"[AUTOSAR Helper] Setting function at {hex(current_function.start)} as 'Det_ReportError' - START")
        rename_helper = MarkErrorHandlingFunc(bv,current_function.start)
        rename_helper.start()
        print(f"[AUTOSAR Helper] Setting function at {hex(current_function.start)} as 'Det_ReportError' - DONE")
        print(f"[AUTOSAR Helper] Note: If there are some functions that were not renamed, re-run this operation again :)")
    case 3:
        print(f"[AUTOSAR Helper] Marking all functions that perform Read/Write operations - START")
        mark_funcs = MarkReadWriteFuncs(bv)
        mark_funcs.start()
        print(f"[AUTOSAR Helper] Marking all functions that perform Read/Write operations - DONE")
        print(f"[AUTOSAR Helper] Results are in index: 'AUTOSAR Functions to investigate (Read/Write operations)'")
    case _:
        print("[AUTOSAR Helper] No choice selected.")
