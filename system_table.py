from binaryninja import (BinaryView, BackgroundTask, PointerType, NamedTypeReferenceType, HighLevelILCallSsa,
                         SSAVariable, Constant, HighLevelILAssign, HighLevelILAssignMemSsa, HighLevelILDerefSsa,
                         Function, HighLevelILDerefFieldSsa, HighLevelILVarInitSsa, HighLevelILVarSsa,
                         StructureType, log_info, HighLevelILOperation)
from typing import List

types_to_propagate = {
    "EFI_SYSTEM_TABLE": "SystemTable",
    "EFI_RUNTIME_SERVICES": "RuntimeServices",
    "EFI_BOOT_SERVICES": "BootServices",
    "EFI_MM_SYSTEM_TABLE": "MmSystemTable",
    "EFI_SMM_SYSTEM_TABLE2": "SmmSystemTable",
    "EFI_HANDLE": "GlobalHandle",
}


def get_type_name(typ):
    if isinstance(typ, PointerType):
        if isinstance(typ.target, NamedTypeReferenceType):
            return typ.target.name
        return str(typ.target).split(" ")[-1]

    if isinstance(typ, NamedTypeReferenceType):
        return typ.name


def propagate_variable_uses(bv: BinaryView, func: Function, var: SSAVariable, func_queue: List[Function]) -> bool:
    global types_to_propagate
    updates = False

    for use in func.hlil.ssa_form.get_ssa_var_uses(var):
        instr = use.parent
        if isinstance(instr, HighLevelILCallSsa) or instr.operation == HighLevelILOperation.HLIL_TAILCALL:
            # Function call, propagate the variable type to the function call target
            target = instr.dest
            if not isinstance(target, Constant):
                continue
            target = bv.get_function_at(target.constant)
            if not target:
                continue

            for param_idx in range(len(instr.params)):
                if instr.params[param_idx] == use:
                    type_name = get_type_name(var.type)
                    if param_idx >= len(target.parameter_vars):
                        continue
                    target.parameter_vars[param_idx].type = var.type
                    if type_name in types_to_propagate:
                        target.parameter_vars[param_idx].name = types_to_propagate[type_name]
                    if target not in func_queue:
                        func_queue.append(target)
                    updates = True
        elif isinstance(instr, HighLevelILAssignMemSsa):
            # Assignment, propagate the variable type if it is assigning to a global variable
            target = instr.dest
            if not isinstance(target, HighLevelILDerefSsa):
                continue
            target = target.src
            if not isinstance(target, Constant):
                continue

            type_name = get_type_name(var.type)
            bv.define_user_data_var(target.constant, var.type, types_to_propagate.get(type_name))
            updates = True
        elif isinstance(instr, HighLevelILDerefFieldSsa):
            # Dereferencing field, see if it is a field for a type we want to propagate
            expr_type = instr.expr_type
            if not isinstance(expr_type, PointerType):
                continue
            if not isinstance(expr_type.target, StructureType):
                continue
            if expr_type.target.registered_name.name not in types_to_propagate.keys():
                continue

            # See if this is an assignment to a variable, and propagate that variable if so
            deref_parent = instr.parent
            if isinstance(deref_parent, HighLevelILVarInitSsa):
                target = deref_parent.dest
            elif isinstance(deref_parent, HighLevelILAssign):
                target = deref_parent.dest
                if not isinstance(target, HighLevelILVarSsa):
                    continue
                target = target.var
            elif isinstance(deref_parent, HighLevelILAssignMemSsa):
                # Assignment to memory, if assigning to a global variable, propagate directly
                target = deref_parent.dest
                if not isinstance(target, HighLevelILDerefSsa):
                    continue
                target = target.src
                if not isinstance(target, Constant):
                    continue

                log_info(f"Propagating {expr_type.target.registered_name.name} pointer to data variable at {hex(target.constant)}")
                bv.define_user_data_var(target.constant, expr_type,
                                        types_to_propagate[expr_type.target.registered_name.name])
                updates = True
                continue
            else:
                continue

            func.create_user_var(target.var, expr_type, types_to_propagate[expr_type.target.registered_name.name])
            propagate_variable_uses(bv, func, target, func_queue)
            updates = True

    return updates


def propagate_system_table_pointers(bv: BinaryView, task: BackgroundTask):
    # Add entry function to the list of functions in which to propagate.
    func_queue = []
    entry_func = bv.entry_function
    if entry_func:
        func_queue.append(entry_func)

    # Propagate system table and services tables

    # Process functions until there is no more propagation to be done
    while len(func_queue) > 0:
        if task.cancelled:
            return False

        func = func_queue.pop()

        # Go through the list of parameter variables to see if there are any that need to be propagated
        parameter_vars = func.parameter_vars
        updates = False
        for param_idx in range(len(parameter_vars)):
            param = parameter_vars[param_idx]

            propagate = False
            if isinstance(param.type, PointerType):
                if isinstance(param.type.target, NamedTypeReferenceType):
                    propagate = True
            elif isinstance(param.type, NamedTypeReferenceType):
                if isinstance(param.type.target(bv), PointerType):
                    propagate = True
            if not propagate:
                continue

            updates |= propagate_variable_uses(bv, func, SSAVariable(param, 0), func_queue)

        if updates:
            bv.update_analysis_and_wait()

    # Set types of known Windows bootloader pointers, as these go through several translation layers
    # before arriving at the global variables.
    sym = bv.get_symbol_by_raw_name("EfiST")
    if sym is not None:
        bv.define_user_data_var(sym.address, "EFI_SYSTEM_TABLE*", "EfiST")
    sym = bv.get_symbol_by_raw_name("EfiBS")
    if sym is not None:
        bv.define_user_data_var(sym.address, "EFI_BOOT_SERVICES*", "EfiBS")
    sym = bv.get_symbol_by_raw_name("EfiRT")
    if sym is not None:
        bv.define_user_data_var(sym.address, "EFI_RUNTIME_SERVICES*", "EfiRT")
    sym = bv.get_symbol_by_raw_name("EfiConOut")
    if sym is not None:
        bv.define_user_data_var(sym.address, "EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*", "EfiConOut")
    sym = bv.get_symbol_by_raw_name("EfiConIn")
    if sym is not None:
        bv.define_user_data_var(sym.address, "EFI_SIMPLE_TEXT_INPUT_PROTOCOL*", "EfiConIn")

    bv.update_analysis_and_wait()
    return True
