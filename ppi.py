"""
This module contains functions related to resolving PEI services and PPI protocols
"""
from typing import Optional
from binaryninja import BinaryView, MediumLevelILCall, MediumLevelILTailcall, MediumLevelILLoadStruct, PointerType, \
    MediumLevelILConstPtr, BackgroundTask, HighLevelILAssign, HighLevelILIntrinsic, ILIntrinsic, log_warn, \
    MediumLevelILIntrinsic, MediumLevelILConst, NamedTypeReferenceType, MediumLevelILSetVar, HighLevelILVarInit, \
    MediumLevelILIntrinsicSsa, ILException, Type
from .protocols import define_protocol_types, lookup_and_define_guid
from .system_table import propagate_function_param_types
from .utils import non_conflicting_symbol_name, remove_type_prefix_suffix, get_var_name_from_type, get_type


def define_pei_pointers(bv: BinaryView, task: BackgroundTask) -> bool:
    """
    EFI_PEI_SERVICES can be retrieved by inline assembly code snippets, resolve EFI_PEI_SERVICES pointers according to
    platforms.
    """
    if bv.arch.name in ['x86', 'x86_64']:
        return define_pei_idt(bv, task)
    if bv.arch.name == 'aarch64':
        return define_pei_mrs(bv, task)
    if bv.arch.name in ['thumb2', 'armv7']:
        return define_pei_mrc(bv, task)
    log_warn(f"Resolving Assembly PEI Services pointers not supported for {bv.arch.name}.")
    return False


def define_pei_mrc(bv: BinaryView, task: BackgroundTask) -> bool:
    """
    For ARMv7, the EFI_PEI_SERVICES** is stored in the TPIDRURW read/write Software Thread ID register
    defined in the ARMv7-A Architectural Reference Manual.
    """
    pei_service_pointer = Type.pointer(bv.arch, Type.pointer(bv.arch, get_type(bv, "EFI_PEI_SERVICES")))
    for instr in bv.mlil_instructions:
        if task.cancelled:
            return False
        if isinstance(instr, MediumLevelILIntrinsic):
            if not instr.intrinsic.name == 'Coproc_GetOneWord':
                continue
            if not len(instr.params) == 5:
                continue
            # the parameter should be 0xf, 0, 0xd, 0, 2
            value = [0xf, 0, 0xd, 0, 2]
            mrc = True
            for idx in range(5):
                param = instr.params[idx]
                if not isinstance(param, MediumLevelILConst):
                    continue
                if param.constant != value[idx]:
                    mrc = False
                    break
            if not mrc:
                continue
            instr.output[0].type = pei_service_pointer
    return True


def define_pei_mrs(bv: BinaryView, task):
    """
    For AARCH64, the PEI_SERVICES pointer is stored in TPIDREL0 register, mark return type of `_ReadStatusReg` to
    `EFI_PEI_SERVICES**`.
    """
    pei_service_pointer = Type.pointer(bv.arch, Type.pointer(bv.arch, get_type(bv, "EFI_PEI_SERVICES")))
    for instr in bv.mlil_instructions:
        if task.cancelled:
            return False
        if isinstance(instr, MediumLevelILIntrinsic):
            if not instr.intrinsic.name == '_ReadStatusReg':
                continue
            # if it reading tpidr_el0
            if not instr.params[0].var.name == 'tpidr_el0':
                continue
            # set the type
            instr.output[0].type = pei_service_pointer
    return True


def define_pei_idt(bv: BinaryView, task: BackgroundTask) -> bool:
    """
    This function will define EFI_PEI_SERVICES pointers in x86 and x86_64 platform.
    According to UEFI PI Specification, for x86 and x86_64, EFI_PEI_SERVICES can be accessed via `IDTR`
    """
    intrinsic_target_name = {
        # For X86 processors, the EFI_PEI_SERVICES** is stored in the 4 bytes immediately preceding the
        # Interrupt Descriptor Table.
        'x86': ('__sidt_mems', 'IDTR32'),
        # For x64 processors, the EFI_PEI_SERVICES** is stored in eight bytes immediately preceding the
        # Interrupt Descriptor Table.
        'x86_64': ('__sidt_mems', 'IDTR64'),
    }

    operand_name, intrinsic_type = intrinsic_target_name[bv.arch.name]
    intrinsic_type = get_type(bv, intrinsic_type)
    if not intrinsic_type:
        log_warn("Cannot find IDTR type, Your version of Binary Ninja may be out of date, please consider manually adding those definition or updating to new version.")
        return False
    for instr in bv.hlil_instructions:
        if task.cancelled:
            return False

        if isinstance(instr, HighLevelILAssign):
            if (
                not isinstance(instr.src, HighLevelILIntrinsic)
                or not instr.src.operands
                or not isinstance(instr.src.operands[0], ILIntrinsic)
                or not instr.src.operands[0].name == operand_name
                or not instr.dest.vars
            ):
                continue
            instr.dest.vars[0].type = intrinsic_type

        elif isinstance(instr, HighLevelILVarInit):
            mlils = instr.mlils
            for mlil in mlils:
                if (
                    isinstance(mlil, MediumLevelILIntrinsicSsa)
                    and mlil.intrinsic.name == operand_name
                    and len(mlil.output) > 0
                ):
                    mlil.output[0].var.type = intrinsic_type

    # TODO there is a type propagation issue (vector35/binaryninja#759) related to indirect struct access in core,
    #  manually fix it now, the following should be removed after the bug is fixed.
    for ref in bv.get_code_refs_for_type("EFI_PEI_SERVICES"):
        # This pattern accounts for an API change in ref.mlil and ensures the plugin works with all versions of Binja
        # See https://github.com/Vector35/binaryninja-api/issues/6020 for more details
        try:
            instr = ref.mlil
            if instr is None: raise ILException()
        except ILException:
            log_warn(f"mlil not available at {hex(ref.address)}")
            continue
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if not isinstance(instr.src, MediumLevelILLoadStruct):
            continue
        # manually propagate the type
        instr.dest.type = instr.src.expr_type

    return True


def _define_descriptor(bv: BinaryView, task: BackgroundTask, descriptor_type, param) -> Optional[bool]:
    """
    Define the descriptor type at `param`'s address. The `param` should be a ConstPtr parameter.
    If the analysis got cancelled or encountered an error, return False. If it doesn't meet conditions, return None.
    """
    if not isinstance(param, MediumLevelILConstPtr):
        return

    var_addr = param.constant

    var = bv.get_data_var_at(var_addr)
    if var:
        if descriptor_type == var.type:
            # already defined
            return
    sym = bv.get_symbol_at(var_addr)

    if sym is not None:
        var_name = sym.name
    else:
        var_name = None

    bv.define_user_data_var(var_addr, descriptor_type, var_name)
    bv.update_analysis_and_wait()

    var = bv.get_data_var_at(var_addr)
    notify_descriptor = var.value

    if not isinstance(notify_descriptor, dict):
        return
    if "Guid" not in notify_descriptor:
        return

    # define types for guid and notify entrypoint
    protocol_name = lookup_and_define_guid(bv, notify_descriptor["Guid"])
    if protocol_name is False:
        return False

    if "Notify" in notify_descriptor:
        notify_entrypoint = notify_descriptor['Notify']
        func = bv.get_function_at(notify_entrypoint)
        if not func:
            return
        if not protocol_name:
            func_name = non_conflicting_symbol_name(bv, "UnknownNotify")
        else:
            func_name = non_conflicting_symbol_name(bv, f"Notify{get_var_name_from_type(protocol_name)}")
        func.type = f"EFI_STATUS {func_name}(EFI_PEI_SERVICES **PeiServices, EFI_PEI_NOTIFY_DESCRIPTOR* NotifyDescriptor, VOID* Ppi)"
        bv.update_analysis_and_wait()
        return propagate_function_param_types(bv, task, func)

    return True


def define_pei_descriptor(bv: BinaryView, task: BackgroundTask) -> bool:
    """
    Defines PEI related descriptors, currently this function will only define EFI_PEI_NOTIFY_DESCRIPTOR
    and EFI_PEI_PPI_DESCRIPTOR, which may be used by PEI_SERVICES. Protocol related descriptors are not
    supported yet.
    """
    descriptor_types_names = ["EFI_PEI_NOTIFY_DESCRIPTOR", "EFI_PEI_PPI_DESCRIPTOR"]
    descriptor_types = [get_type(bv, des) for des in descriptor_types_names]
    for descriptor_type in descriptor_types:
        refs = list(bv.get_code_refs_for_type(descriptor_type))
        for ref in refs:
            if task.cancelled:
                return False

            try:
                instr = ref.mlil
                if instr is None: raise ILException()
            except ILException:
                log_warn(f"mlil unavailable for ref: {hex(ref.address)}")
                continue

            if (
                    not isinstance(instr, (MediumLevelILCall, MediumLevelILTailcall))
                    or not isinstance(instr.dest, MediumLevelILLoadStruct)
                    or not isinstance(instr.dest.expr_type, PointerType)
            ):
                continue

            function_type = instr.dest.expr_type.target
            params = function_type.parameters
            target_param = None
            for param in params:
                type_name = str(param.type)
                if (
                        not isinstance(param.type, PointerType)
                        or not isinstance(param.type.target, NamedTypeReferenceType)
                ):
                    continue
                if remove_type_prefix_suffix(type_name) in descriptor_types_names:
                    target_param = params.index(param)
                    break
            if target_param is None:
                continue

            if _define_descriptor(bv, task, descriptor_type, instr.params[target_param]) is False:
                return False
    return True


def define_locate_ppi_types(bv: BinaryView, task: BackgroundTask) -> bool:
    """
    define PPI protocols by resolving invocations of LocatePpi
    """
    return define_protocol_types(bv, "EFI_PEI_SERVICES", "LocatePpi", 1, 4, task)
