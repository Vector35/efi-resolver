import struct
from typing import Dict, List
from binaryninja import BinaryView, log_info, RegisterValueType, TypeFieldReference, HighLevelILVarInitSsa, \
    HighLevelILVarSsa, Constant, StructureType, NamedTypeReferenceType
from binaryninja.mediumlevelil import MediumLevelILCallSsa, MediumLevelILTailcallSsa, MediumLevelILLoadStructSsa, \
    MediumLevelILVarSsa
from ..spec import protocol_binding_services, smm_protocol_binding_services, mm_protocol_binding_services, pei_ppi_services
from .utils import non_conflicting_variable_name, get_var_name_from_type
from .propagate import propagate_type_to_data
from ..util import logger


def define_protocol_types(bv: BinaryView, type_name: str, binding_struct_info: Dict, protocol_db: Dict,
                          guid_db: Dict) -> None:
    """
    Find reference of `type_name`, and define protocols according to the information in `binding_struct_info`.
    If protocol type can be found, define for the `interface` parameter.

    :param bv: Binary View
    :param type_name: Type name to find reference
    :param binding_struct_info: a dictionary (offset-dictionary pair) containing the protocol-related call information.
        Each item should contain a `guid` key and an `interface` key.
    :param protocol_db: a dictionary maps from guid bytes to (guid_name, protocol_name) tuples.
    :param guid_db: a dictionary maps used for searching possible guid names

    :return: None
    """
    struct_type = bv.types[type_name]
    if not isinstance(struct_type, StructureType):
        logger.log_warn(f"[define_protocol_types] {type_name} is not a structure type")
        return

    for offset in binding_struct_info.keys():
        guid_param = binding_struct_info[offset].get("guid")
        interface_param = binding_struct_info[offset].get("interface")

        if (guid_param is None) or (interface_param is None):
            logger.log_warn(f"[define_protocol_types] binding_struct_info for {type_name} at offset {offset} is wrong")
            continue

        refs = list(bv.get_code_refs_for_type_field(type_name, offset))
        for ref in refs:
            instr = None
            for il in ref.func.mlil.instructions:
                if il.address == ref.address:
                    instr = il.ssa_form
                    break
            if instr is None:
                continue

            if not (isinstance(instr, MediumLevelILCallSsa) or isinstance(instr, MediumLevelILTailcallSsa)):
                continue

            if not isinstance(instr.dest, MediumLevelILLoadStructSsa):
                continue

            if isinstance(ref, TypeFieldReference):
                func = ref.func
            else:
                func = ref.function

            guid = None
            guid_addr = instr.params[guid_param].value
            if guid_addr.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue]:
                # if the guid parameter it's not a constant pointer, define the variable directly

                var = bv.get_data_var_at(guid_addr.value)
                if var:
                    if isinstance(var.type, NamedTypeReferenceType):
                        if var.type.name == "EFI_GUID":
                            # this variable has already been defined
                            # but we still want to define the interface type
                            pass
                guid = bv.read(guid_addr.value, 16)
                if not guid or len(guid) < 16:
                    continue

            elif guid_addr.type == RegisterValueType.StackFrameOffset:
                # if it's a guid in stack
                idx = 0
                guid = b""
                while idx < 16:
                    var = instr.get_var_for_stack_location(guid_addr.value + idx)
                    if var is None or var.type is None:
                        break
                    width = var.type.width
                    if width == 0 or width > 8:
                        break
                    value = instr.get_stack_contents(guid_addr.value + idx, width)
                    if value.type in [RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue]:
                        value = value.value
                    else:
                        break
                    guid += struct.pack("<Q", value)[0:width]
                    idx += width
                if len(guid) != 16:
                    continue

            elif isinstance(instr.params[guid_param], MediumLevelILVarSsa):
                # check if the GUID variable is an incoming parameter
                # if so, we need to define the parameter type
                # TODO this branch haven't been read line-by-line
                ssa_var = instr.params[guid_param].var
                if ssa_var.version != 0:
                    incoming_def = func.hlil.get_ssa_var_definition(ssa_var)
                    if incoming_def is None:
                        continue
                    incoming_def = incoming_def.ssa_form
                    if not isinstance(incoming_def, HighLevelILVarInitSsa):
                        continue
                    if not isinstance(incoming_def.src, HighLevelILVarSsa):
                        continue
                    if incoming_def.src.var.version != 0:
                        continue
                    ssa_var = incoming_def.src.var

                incoming_interface_param_idx = None
                for i in range(len(func.parameter_vars)):
                    if func.parameter_vars[i] == ssa_var.var:
                        incoming_interface_param_idx = i
                        break
                if incoming_interface_param_idx is None:
                    continue

                # this call is a protocol wrapper, need to resolve calls to this function
                logger.log_info(f"Found protocol wrapper at {hex(ref.address)}")
                # TODO resolve all callers of func

            if not guid:
                continue

            protocol_type_name, guid_name = protocol_db.get(guid, (None, None))
            if guid_name is None:
                guid_name = guid_db.get(guid, None)
                if not guid_name:
                    guid_name = non_conflicting_variable_name(bv, "UNKNOWN_GUID")
                    logger.log_info(f"Found Unknown GUID at {hex(ref.address)}")

                logger.log_info(f"Found {guid_name} at {hex(ref.address)}, but no type information is available")

            sym = bv.get_symbol_at(guid_addr.value)
            if sym is not None:
                # if already defined, keep the name unchanged
                if sym.name != guid_name:
                    log_info(
                        f"EFI_GUID already got a name: {sym.name}, another possible name: {guid_name} according to {hex(ref.address)}")
                    guid_name = sym.name
            bv.define_user_data_var(guid_addr.value, "EFI_GUID", guid_name)
            logger.log_info(f"[resolve_protocol] define GUID {guid_name} at {hex(guid_addr.value)}")
            bv.update_analysis()

            # define interface type (if applicable)
            interface = instr.params[interface_param]
            if not protocol_type_name:
                protocol_type_name = "VOID"
                # this is a protocol we don't have the type info
                # TODO maybe we can do some analysis and infer the interface type
                #  we can define (typedef) a name for it temporarily

            if isinstance(interface, Constant):
                # a protocol interface is stored as a global variable pointer
                var_addr = interface.constant
                sym = bv.get_symbol_at(var_addr)
                name = non_conflicting_variable_name(bv, get_var_name_from_type(guid_name))
                if sym is not None:
                    name = sym.name
                bv.define_user_data_var(var_addr, f"{protocol_type_name}*", name)
                logger.log_info(f"Setting type {protocol_type_name}* for global variable at {hex(var_addr)}")
                bv.update_analysis()

            elif isinstance(interface, MediumLevelILVarSsa):
                # this is typically an interface variable pointer used inside the function
                # we should define the var and try to apply the types
                if not interface.hlil.src:
                    continue
                user_var = interface.hlil.src.var
                if not user_var:
                    continue

                if protocol_type_name == "VOID":
                    interface_name = non_conflicting_variable_name(bv, get_var_name_from_type("UNKNOWN_INTERFACE"))
                else:
                    interface_name = non_conflicting_variable_name(bv, get_var_name_from_type(protocol_type_name))
                func.create_user_var(user_var, f"{protocol_type_name}*", interface_name)
                logger.log_info(f"Creating {protocol_type_name}* for {interface_name}")
                bv.update_analysis_and_wait()


def resolve_protocols(bv: BinaryView, protocol_db: Dict, guid_db: Dict) -> None:
    """
    Resolving protocol bindings, support `LocateProtocol', 'HandleProtocol' and `OpenProtocol`.
    Before this call, `BootServices` should have been properly propagated.
    If protocol types are available, the interface parameter will be defined as the protocol type.

    :param bv: Binary View
    :param protocol_db: Dictionary of protocol definitions
    :param guid_db: Dictionary of GUID definitions
    """
    define_protocol_types(bv, "EFI_BOOT_SERVICES", protocol_binding_services, protocol_db, guid_db)


def resolve_ppis(bv: BinaryView, protocol_db: Dict, guid_db: Dict):
    """
    Resolve PPIs, EFI_PEI_SERVICES should have already been propagated in the entry point
    Steps:
      1. Define EFI_PEI_NOTIFY_DESCRIPTOR, and it's fields.
      2. Propagate parameters for Notify Entrypoint (after this the types should be well propagated)
      3. Resolve PPIs by handling protocol related services. (only LocatePpi for now)
    """

    # After defining the DESCRIPTOR, we need to follow the function pointer and the GUID pointer
    propagate_type_to_data(bv, "EFI_PEI_NOTIFY_DESCRIPTOR", name_dict=guid_db, follow_field=True)
    propagate_type_to_data(bv, "EFI_PEI_PPI_DESCRIPTOR", name_dict=guid_db, follow_field=True)

    # Now that we have defined the entry point, we want to analyze the ppi now
    define_protocol_types(bv, "EFI_PEI_SERVICES", pei_ppi_services, protocol_db, guid_db)


def resolve_mm_protocols(bv: BinaryView, protocol_db: Dict, guid_db: Dict) -> None:
    """
    define SMM/MM system table, and resolve SMM related protocol calls
    """
    # to resolve mm protocols, we just need to define SmSt pointers
    propagate_type_to_data(bv, "EFI_MM_SYSTEM_TABLE", var_name="MmSystemTable", pointer=True)
    propagate_type_to_data(bv, "EFI_SMM_SYSTEM_TABLE2", var_name="SmmSystemTable", pointer=True)

    define_protocol_types(bv, "EFI_SMM_SYSTEM_TABLE2", smm_protocol_binding_services, protocol_db, guid_db)
    define_protocol_types(bv, "EFI_MM_SYSTEM_TABLE", mm_protocol_binding_services, protocol_db, guid_db)
