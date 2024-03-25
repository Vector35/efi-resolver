from binaryninja import (BinaryView, BackgroundTask, HighLevelILCall, RegisterValueType, HighLevelILAddressOf,
                         HighLevelILVar, Constant, Function, HighLevelILVarSsa, HighLevelILVarInitSsa,
                         TypeFieldReference, bundled_plugin_path, log_info, log_warn, log_alert)
from typing import Optional, Tuple
import os
import sys
import struct

protocols = None

def init_protocol_mapping():
    # Parse EFI definitions only once
    global protocols
    if protocols is not None:
        return True

    # Find the EFI type definition file within the Binary Ninja installation
    if sys.platform == "darwin":
        efi_def_path = os.path.join(bundled_plugin_path(), "..", "..", "Resources", "types", "efi.c")
    else:
        efi_def_path = os.path.join(bundled_plugin_path(), "..", "types", "efi.c")

    # Try to read the EFI type definitions. This may not exist on older versions of Binary Ninja.
    try:
        efi_defs = open(efi_def_path, "r").readlines()
    except:
        log_alert(f"Could not open EFI type definition file at '{efi_def_path}'. Your version of Binary Ninja may be out of date. Please update to version 3.5.4331 or higher.")
        return False

    protocols = {}

    # Parse the GUID to protocol structure mappings out of the type definition source
    guids = []
    for line in efi_defs:
        if line.startswith("///@protocol"):
            guid = line.split("///@protocol")[1].replace("{", "").replace("}", "").strip().split(",")
            guid = [int(x, 16) for x in guid]
            guid = struct.pack("<IHHBBBBBBBB", *guid)
            guids.append((guid, None))
        elif line.startswith("///@binding"):
            guid_name = line.split(" ")[1]
            guid = line.split(" ")[2].replace("{", "").replace("}", "").strip().split(",")
            guid = [int(x, 16) for x in guid]
            guid = struct.pack("<IHHBBBBBBBB", *guid)
            guids.append((guid, guid_name))
        elif line.startswith("struct"):
            name = line.split(" ")[1].strip()
            for guid_info in guids:
                guid, guid_name = guid_info
                if guid_name is None:
                    protocols[guid] = (name, f"{name}_GUID")
                else:
                    protocols[guid] = (name, guid_name)
        else:
            guids = []

    return True

def lookup_protocol_guid(guid: bytes) -> Optional[Tuple[str, str]]:
    global protocols
    if guid in protocols:
        return protocols[guid]
    return (None, None)

def variable_name_for_protocol(protocol: str) -> str:
    name = protocol
    if name.startswith("EFI_"):
        name = name[4:]
    if name.endswith("_GUID"):
        name = name[:-5]
    if name.endswith("_PROTOCOL"):
        name = name[:-9]
    case_str = ""
    first = True
    for c in name:
        if c == "_":
            first = True
            continue
        elif first:
            case_str += c.upper()
            first = False
        else:
            case_str += c.lower()
    return case_str

def nonconflicting_variable_name(func: Function, base_name: str) -> str:
    idx = 0
    name = base_name
    while True:
        ok = True
        for var in func.vars:
            if var.name == name:
                ok = False
                break
        if ok:
            break
        idx += 1
        name = f"{base_name}_{idx}"
    return name

def define_protocol_types_for_refs(bv: BinaryView, func_name: str, refs, guid_param: int, interface_param: int, task: BackgroundTask) -> bool:
    refs = list(refs)
    for ref in refs:
        if task.cancelled:
            return False

        if isinstance(ref, TypeFieldReference):
            func = ref.func
        else:
            func = ref.function

        llil = func.get_llil_at(ref.address, ref.arch)
        if not llil:
            continue
        for hlil in llil.hlils:
            if isinstance(hlil, HighLevelILCall):
                # Check for status transform wrapper function
                if len(hlil.params) == 1 and isinstance(hlil.params[0], HighLevelILCall):
                    hlil = hlil.params[0]

                # Found call to target field
                if len(hlil.params) <= max(guid_param, interface_param):
                    continue

                # Get GUID parameter and read it from the binary or the stack
                guid_addr = hlil.params[guid_param].value
                guid = None
                if guid_addr.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue]:
                    guid = bv.read(guid_addr.value, 16)
                    if not guid or len(guid) < 16:
                        continue
                elif guid_addr.type == RegisterValueType.StackFrameOffset:
                    mlil = hlil.mlil
                    if mlil is None:
                        continue
                    guid = b""
                    offset = 0
                    while offset < 16:
                        var = mlil.get_var_for_stack_location(guid_addr.value + offset)
                        if var is None or var.type is None:
                            break
                        width = var.type.width
                        if width == 0 or width > 8:
                            break
                        value = mlil.get_stack_contents(guid_addr.value + offset, width)
                        if value.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue]:
                            value = value.value
                        else:
                            break
                        guid += struct.pack("<Q", value)[0:width]
                        offset += width
                    if len(guid) != 16:
                        continue
                elif isinstance(hlil.params[guid_param], HighLevelILVar):
                    # See if GUID variable is an incoming parameter
                    ssa = hlil.params[guid_param].ssa_form
                    if ssa is None or not isinstance(ssa, HighLevelILVarSsa):
                        continue
                    if ssa.var.version != 0:
                        incoming_def = func.hlil.get_ssa_var_definition(ssa.var)
                        if incoming_def is None:
                            continue
                        incoming_def = incoming_def.ssa_form
                        if not isinstance(incoming_def, HighLevelILVarInitSsa):
                            continue
                        if not isinstance(incoming_def.src, HighLevelILVarSsa):
                            continue
                        if incoming_def.src.var.version != 0:
                            continue
                        ssa = incoming_def.src

                    # Find index of incoming parameter
                    incoming_guid_param_idx = None
                    for i in range(len(func.parameter_vars)):
                        if func.parameter_vars[i] == ssa.var.var:
                            incoming_guid_param_idx = i
                            break
                    if incoming_guid_param_idx is None:
                        continue

                    # See if output interface variable is an incoming parameter
                    ssa = hlil.params[interface_param].ssa_form
                    if ssa is None or not isinstance(ssa, HighLevelILVarSsa):
                        continue
                    if ssa.var.version != 0:
                        incoming_def = func.hlil.get_ssa_var_definition(ssa.var)
                        if incoming_def is None:
                            continue
                        incoming_def = incoming_def.ssa_form
                        if not isinstance(incoming_def, HighLevelILVarInitSsa):
                            continue
                        if not isinstance(incoming_def.src, HighLevelILVarSsa):
                            continue
                        if incoming_def.src.var.version != 0:
                            continue
                        ssa = incoming_def.src

                    # Find index of incoming parameter
                    incoming_interface_param_idx = None
                    for i in range(len(func.parameter_vars)):
                        if func.parameter_vars[i] == ssa.var.var:
                            incoming_interface_param_idx = i
                            break
                    if incoming_interface_param_idx is None:
                        continue

                    # This function is a wrapper, resolve protocols for calls to this function
                    log_info(f"Found EFI protocol wrapper {func_name} at {hex(ref.address)}, checking references to wrapper function")
                    if not define_protocol_types_for_refs(bv, func.name, bv.get_code_refs(func.start),
                                                          incoming_guid_param_idx, incoming_interface_param_idx, task):
                        return False
                    continue

                if guid is None:
                    continue

                # Get the protocol from the GUID
                protocol, guid_name = lookup_protocol_guid(guid)
                if protocol is None:
                    log_warn(f"Unknown EFI protocol {guid.hex()} referenced at {hex(ref.address)}")
                    continue

                # Rename the GUID with the protocol name
                sym = bv.get_symbol_at(guid_addr.value)
                name = guid_name
                if sym is not None:
                    name = sym.name
                bv.define_user_data_var(guid_addr.value, "EFI_GUID", name)

                # Get interface pointer parameter and set it to the type of the protocol
                dest = hlil.params[interface_param]
                if isinstance(dest, HighLevelILAddressOf):
                    dest = dest.src
                    if isinstance(dest, HighLevelILVar):
                        dest = dest.var
                        log_info(f"Setting type {protocol}* for local variable in {func_name} call at {hex(ref.address)}")
                        name = nonconflicting_variable_name(func, variable_name_for_protocol(guid_name))
                        func.create_user_var(dest, f"{protocol}*", name)
                elif isinstance(dest, Constant):
                    dest = dest.constant
                    log_info(f"Setting type {protocol}* for global variable at {hex(dest)} in {func_name} call at {hex(ref.address)}")
                    sym = bv.get_symbol_at(dest)
                    name = f"{variable_name_for_protocol(guid_name)}_{dest:x}"
                    if sym is not None:
                        name = sym.name
                    bv.define_user_data_var(dest, f"{protocol}*", name)

    bv.update_analysis_and_wait()
    return True

def define_system_table_types_for_refs(
    bv: BinaryView,
    func_name: str,
    refs,
    table_param: int,
    type_name: str,
    var_name: str,
    task: BackgroundTask,
) -> bool:
    print(type(refs))
    for ref in list(refs):
        if task.cancelled:
            return False

        if isinstance(ref, TypeFieldReference):
            func = ref.func
        else:
            func = ref.function

        llil = func.get_llil_at(ref.address, ref.arch)
        if not llil:
            continue

        for hlil in llil.hlils:
            if isinstance(hlil, HighLevelILCall):
                if len(hlil.params) <= table_param:
                    continue

                dest = hlil.params[table_param]
                if isinstance(dest, HighLevelILAddressOf):
                    dest = dest.src
                    if isinstance(dest, HighLevelILVar):
                        dest = dest.var
                        log_info(
                            f"Setting type {type_name}* for local variable in {func_name} call at {hex(ref.address)}"
                        )
                        name = nonconflicting_variable_name(func, var_name)
                        func.create_user_var(dest, f"{type_name}*", name)
                elif isinstance(dest, Constant):
                    dest = dest.constant
                    log_info(
                        f"Setting type {type_name}* for global variable at {hex(dest)} in {func_name} call at {hex(ref.address)}"
                    )
                    sym = bv.get_symbol_at(dest)
                    name = var_name
                    if sym is not None:
                        name = sym.name
                    bv.define_user_data_var(dest, f"{type_name}*", name)

    bv.update_analysis_and_wait()
    return True

def define_protocol_types(bv: BinaryView, field: str, guid_param: int, interface_param: int, task: BackgroundTask) -> bool:
    boot_services = bv.types["EFI_BOOT_SERVICES"]
    offset = None
    for member in boot_services.members:
        if member.name == field:
            offset = member.offset
            break
    if offset is None:
        log_warn(f"Could not find {field} member in EFI_BOOT_SERVICES")
        return True

    return define_protocol_types_for_refs(bv, field, bv.get_code_refs_for_type_field("EFI_BOOT_SERVICES", offset),
                                          guid_param, interface_param, task)

def define_system_table_types(
    bv: BinaryView,
    service_name: str,
    field: str,
    table_param: int,
    type_name: str,
    var_name: str,
    task: BackgroundTask,
) -> bool:
    service = bv.types[service_name]
    for member in service.members:
        if member.name == field:
            offset = member.offset
            break

    if offset is None:
        log_warn(f"Could not find {field} member in {service_name}")

    return define_system_table_types_for_refs(
        bv, field, bv.get_code_refs_for_type_field(service_name, offset), table_param, type_name, var_name, task
    )

def define_handle_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "HandleProtocol", 1, 2, task)

def define_open_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "OpenProtocol", 1, 2, task)

def define_locate_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "LocateProtocol", 0, 2, task)

def define_locate_mm_system_table_types(bv: BinaryView, task: BackgroundTask) -> bool:
    if not define_system_table_types(
        bv, "EFI_SMM_BASE2_PROTOCOL", "GetSmstLocation", 1, "EFI_SMM_SYSTEM_TABLE2", "SmmSystemTable", task
    ):
        return False

    return define_system_table_types(
        bv, "EFI_MM_BASE_PROTOCOL", "GetMmstLocation", 1, "EFI_MM_SYSTEM_TABLE", "MmSystemTable", task
    )
