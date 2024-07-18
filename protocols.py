import os
import json
import sys
import struct
from typing import Optional, Tuple, List, Dict
from binaryninja import (BinaryView, BackgroundTask, HighLevelILCall, RegisterValueType, HighLevelILAddressOf,
                         HighLevelILVar, Constant, HighLevelILVarSsa, HighLevelILVarInitSsa, TypeFieldReference,
                         bundled_plugin_path, log_info, log_warn, log_alert, ILException, user_directory, Type,
                         Function, show_message_box)
from binaryninja.enums import MessageBoxButtonSet
from .utils import (non_conflicting_local_variable_name, get_var_name_from_type, non_conflicting_symbol_name,
                    get_type)

protocols: Dict[bytes, Tuple[str, str]] = {}
user_guids: Dict[bytes, str] = {}


def init_protocol_mapping() -> bool:
    """
    Init protocol mappings, this function will parse bundled efi types and user provided types (if applicable)
    If the user-provided mapping files contain errors, it will show a message box containing error position.
    """
    global protocols, user_guids

    if sys.platform == "darwin":
        efi_def_path = os.path.join(bundled_plugin_path(), "..", "..", "Resources", "types", "efi.c")
    else:
        efi_def_path = os.path.join(bundled_plugin_path(), "..", "types", "efi.c")

    user_mapping_path = os.path.join(user_directory(), "types", "efi-guids.json")

    try:
        with open(efi_def_path, "r") as f:
            efi_defs = f.readlines()
    except FileNotFoundError:
        log_alert(f"Could not open EFI type definition file at '{efi_def_path}'. Your version of Binary Ninja may be out of date. Please update to version 3.5.4331 or higher.")
        return False

    protocols = parse_protocol_mapping(efi_defs)

    if os.path.exists(user_mapping_path):
        continue_text = f"\nContinue without {user_mapping_path} protocol bindings?"
        try:
            user_guids = parse_guid_json(user_mapping_path)
        except (AssertionError, ValueError, json.decoder.JSONDecodeError, struct.error) as e:
            flag = show_message_box(f"Parsing protocol mapping {user_mapping_path} error", e.args[0] + continue_text, MessageBoxButtonSet.YesNoButtonSet)
            return bool(flag)

    return True


def parse_guid_json(json_path: str) -> Optional[Dict]:
    """ Input a json filepath, read the content and return the parsed GUID dict """
    result = {}
    with open(json_path, "r") as f:
        guid_json = json.load(f)

        for name, content in guid_json.items():
            guid = struct.pack("<IHH8B", *content)
            result[guid] = name
    return result


def parse_protocol_mapping(efi_defs: List):
    # Parse EFI definitions only once
    protocols = {}

    # Parse the GUID to protocol structure mappings out of the type definition source
    guids = []
    for idx in range(len(efi_defs)):
        line = efi_defs[idx]
        if line.startswith("///@protocol"):
            guid = line.replace("///@protocol", "").replace("{", "").replace("}", "").strip().split(",")
            guid = [int(x, 16) for x in guid]
            guid = struct.pack("<IHHBBBBBBBB", *guid)
            guids.append((guid, None))

        elif line.startswith("///@binding"):
            line = line.split(" ")
            _, guid_name, guid = line
            guid = guid.replace("{", "").replace("}", "").strip().split(",")
            guid = [int(x, 16) for x in guid]
            guid = struct.pack("<IHHBBBBBBBB", *guid)
            guids.append((guid, guid_name))

        elif line.startswith("struct"):
            if not guids:
                continue
            line = line.split(" ")
            name = line[1].strip()
            for guid_info in guids:
                guid, guid_name = guid_info
                if guid_name is None:
                    protocols[guid] = (name, f"{name}_GUID")
                else:
                    protocols[guid] = (name, guid_name)
        else:
            guids = []

    return protocols


def lookup_protocol_guid(guid: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Input guid bytes, lookup the name in user provided guid database and bundled protocol mapping
    """
    global protocols, user_guids
    if guid in user_guids:
        # lookup user provided database first
        return None, user_guids[guid]
    return protocols.get(guid, (None, None))


def lookup_and_define_guid(bv: BinaryView, addr: int) -> bool | Optional[str]:
    """
    Input an address, define the guid there, lookup the protocol mapping and return the protocol name.
    """
    guid = bv.read(addr, 16)
    if not guid or len(guid) != 16:
        return False
    protocol_name, guid_name = lookup_protocol_guid(guid)
    if guid_name is None:
        guid_name = non_conflicting_symbol_name(bv, "UnknownGuid")
    bv.define_user_data_var(addr, 'EFI_GUID', guid_name)

    return protocol_name


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

        try:
            llil = func.get_llil_at(ref.address, ref.arch)
        except ILException:
            continue

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
                    if guid_name:
                        # this is a user-added guid, check whether the related type is added by user
                        possible_protocol_type = guid_name.replace('_GUID', '')
                        if possible_protocol_type in bv.types:
                            protocol = possible_protocol_type
                    else:
                        log_warn(f"Unknown EFI protocol {guid.hex()} referenced at {hex(ref.address)}")
                        guid_name = non_conflicting_symbol_name(bv, "UnknownProtocolGuid")

                # Rename the GUID with the protocol name
                sym = bv.get_symbol_at(guid_addr.value)
                name = guid_name
                if sym is not None:
                    name = sym.name
                bv.define_user_data_var(guid_addr.value, "EFI_GUID", name)

                # Get interface pointer parameter and set it to the type of the protocol
                dest = hlil.params[interface_param]
                if not protocol:
                    # User only added the guid, use VOID* as default type for interfaces
                    protocol = "VOID"
                    log_warn(f"User provided GUID without types: {guid_name}")

                protocol_type = get_type(bv, protocol)
                if not protocol_type:
                    continue
                protocol_type = Type.pointer(bv.arch, protocol_type)
                if isinstance(dest, HighLevelILAddressOf):
                    dest = dest.src
                    if isinstance(dest, HighLevelILVar):
                        dest = dest.var
                        log_info(f"Setting type {protocol}* for local variable in {func_name} call at {hex(ref.address)}")
                        name = non_conflicting_local_variable_name(func, get_var_name_from_type(guid_name))
                        func.create_user_var(dest, protocol_type, name)
                elif isinstance(dest, Constant):
                    dest = dest.constant
                    log_info(f"Setting type {protocol}* for global variable at {hex(dest)} in {func_name} call at {hex(ref.address)}")
                    sym = bv.get_symbol_at(dest)
                    name = f"{get_var_name_from_type(guid_name)}_{dest:x}"
                    if sym is not None:
                        name = sym.name
                    bv.define_user_data_var(dest, protocol_type, name)

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
                type_obj = get_type(bv, type_name)
                if not type_obj:
                    continue
                type_obj = Type.pointer(bv.arch, type_obj)
                if isinstance(dest, HighLevelILAddressOf):
                    dest = dest.src
                    if isinstance(dest, HighLevelILVar):
                        dest = dest.var
                        log_info(
                            f"Setting type {type_name}* for local variable in {func_name} call at {hex(ref.address)}"
                        )
                        name = non_conflicting_local_variable_name(func, var_name)
                        func.create_user_var(dest, type_obj, name)
                elif isinstance(dest, Constant):
                    dest = dest.constant
                    log_info(
                        f"Setting type {type_name}* for global variable at {hex(dest)} in {func_name} call at {hex(ref.address)}"
                    )
                    sym = bv.get_symbol_at(dest)
                    name = var_name
                    if sym is not None:
                        name = sym.name
                    bv.define_user_data_var(dest, type_obj, name)

    bv.update_analysis_and_wait()
    return True

def define_protocol_types(bv: BinaryView, type_name: str, field: str, guid_param: int, interface_param: int, task: BackgroundTask) -> bool:
    struct_type = get_type(bv, type_name)
    if not struct_type:
        return False
    offset = None
    for member in struct_type.members:
        if member.name == field:
            offset = member.offset
            break
    if offset is None:
        log_warn(f"Could not find {field} member in {type_name}")
        return True

    return define_protocol_types_for_refs(bv, field, bv.get_code_refs_for_type_field(type_name, offset),
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
    return define_protocol_types(bv, "EFI_BOOT_SERVICES", "HandleProtocol", 1, 2, task)


def define_open_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_BOOT_SERVICES", "OpenProtocol", 1, 2, task)


def define_locate_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_BOOT_SERVICES", "LocateProtocol", 0, 2, task)


def define_locate_mm_system_table_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_system_table_types(
        bv, "EFI_MM_BASE_PROTOCOL", "GetMmstLocation", 1, "EFI_MM_SYSTEM_TABLE", "MmSystemTable", task
    )


def define_locate_smm_system_table_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_system_table_types(
        bv, "EFI_SMM_BASE2_PROTOCOL", "GetSmstLocation", 1, "EFI_SMM_SYSTEM_TABLE2", "SmmSystemTable", task
    )


def define_mm_locate_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_MM_SYSTEM_TABLE", "MmLocateProtocol", 0, 2, task)


def define_smm_locate_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_SMM_SYSTEM_TABLE2", "SmmLocateProtocol", 0, 2, task)


def define_mm_handle_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_MM_SYSTEM_TABLE", "MmHandleProtocol", 1, 2, task)


def define_smm_handle_protocol_types(bv: BinaryView, task: BackgroundTask) -> bool:
    return define_protocol_types(bv, "EFI_SMM_SYSTEM_TABLE2", "SmmHandleProtocol", 1, 2, task)
