from binaryninja import BinaryView, MediumLevelILCall, MediumLevelILTailcall, MediumLevelILLoadStruct, PointerType, \
    MediumLevelILConstPtr, BackgroundTask
from .protocols import lookup_protocol_guid, define_protocol_types
from .system_table import propagate_system_table_pointers


def define_descriptor(bv: BinaryView, task):
    descriptor_types = ["EFI_PEI_NOTIFY_DESCRIPTOR", "EFI_PEI_PPI_DESCRIPTOR", "EFI_PEI_DESCRIPTOR", ]
    for descriptor_type in descriptor_types:
        refs = list(bv.get_code_refs_for_type(descriptor_type))
        for ref in refs:
            if task.cancelled:
                return False
            instr = ref.mlil
            if isinstance(instr, MediumLevelILCall) or isinstance(instr, MediumLevelILTailcall):
                if isinstance(instr.dest, MediumLevelILLoadStruct):
                    # likely a call to services
                    if isinstance(instr.dest.expr_type, PointerType):
                        function_type = instr.dest.expr_type.target
                        params = function_type.parameters
                        target_param = None
                        for param in params:
                            type_name = str(param.type)
                            if "DESCRIPTOR" in type_name:
                                target_param = params.index(param)
                                break
                        if target_param is None:
                            continue

                        param = instr.params[target_param]
                        if not isinstance(param, MediumLevelILConstPtr):
                            continue

                        var_addr = param.constant
                        sym = bv.get_symbol_at(var_addr)

                        if sym is not None:
                            var_name = sym.name
                        else:
                            var_name = None

                        if type_name[-1] == '*':
                            type_name = type_name[:-1]

                        bv.define_user_data_var(var_addr, type_name, var_name)
                        bv.update_analysis_and_wait()

                        notify_descriptor = bv.get_data_var_at(var_addr).value

                        if not isinstance(notify_descriptor, dict):
                            continue
                        if 'Guid' not in notify_descriptor.keys():
                            continue

                        # define types for guid and notify entrypoint
                        guid = bv.read(notify_descriptor['Guid'], 16)
                        if (not guid) or len(guid) != 16:
                            continue
                        guid_name, protocol_name = lookup_protocol_guid(guid)
                        bv.define_user_data_var(notify_descriptor['Guid'], 'EFI_GUID', guid_name)

                        if 'Notify' in notify_descriptor.keys():
                            notify_entrypoint = notify_descriptor['Notify']
                            func = bv.get_function_at(notify_entrypoint)
                            if not func:
                                continue
                            if protocol_name:
                                func_name = f"Notify_{protocol_name}"
                            else:
                                func_name = f"Notify_UNKNOWN_PPI"
                            func.type = f"EFI_STATUS {func_name}(EFI_PEI_SERVICES **PeiServices, EFI_PEI_NOTIFY_DESCRIPTOR* NotifyDescriptor, VOID* Ppi)"
                            bv.update_analysis_and_wait()
                            if not propagate_system_table_pointers(bv, task, func):
                                return False

                        elif 'Ppi' in notify_descriptor.keys():
                            ppi_addr = notify_descriptor['Ppi']
                            if not protocol_name:
                                ppi_name = 'UNKNOWN_PPI'
                            else:
                                ppi_name = protocol_name
                            bv.define_user_data_var(ppi_addr, 'VOID*', ppi_name)
                            bv.update_analysis_and_wait()

    return True


def define_locate_ppi_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_PEI_SERVICES", "LocatePpi", 1, 4, task)
