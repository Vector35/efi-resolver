"""
This module contains functions related to type propagation.
- `propagate_var_type`: propagates a function's parameter variable to all its usage (and callees)
- `propagate_type_to_function_callsites`: propagate a function's parameter variable's type to all its caller
- `propagate_type_to_data`: finds code references of a type and define related data vars
"""
from binaryninja import BinaryView, Function, Variable, SSAVariable, Constant, RegisterValueType
from binaryninja.types import NamedTypeReferenceType, PointerType, StructureType
from binaryninja.mediumlevelil import MediumLevelILCall, MediumLevelILLoadStruct, MediumLevelILConstPtr, \
    MediumLevelILSetVar, MediumLevelILVar
from binaryninja.highlevelil import HighLevelILCallSsa, HighLevelILTailcall, HighLevelILAssignMemSsa, \
    HighLevelILDerefFieldSsa, HighLevelILDerefSsa, HighLevelILVarInitSsa, HighLevelILAssign, HighLevelILVarSsa, \
    HighLevelILAddressOf, HighLevelILVar, HighLevelILDeref, HighLevelILVarInit
from .utils import get_type_name, get_var_name_from_type, non_conflicting_variable_name, lookup_and_define_guid
from ..util import logger


def propagate_var_type(bv: BinaryView, func: Function, var: Variable) -> None:
    """
    Propagate the variable type through the function and all its callees,
    note that we only propagate pointer to typedefs, or typedef to pointers
    (those have 100% confidence are UEFI related types)

    This is a function-level propagation, which means each time this function
    is invoked, one parameter of one function will be propagated.

    :param bv: the binary view
    :param func: the function to propagate
    :param var: the parameter variable to propagate

    :return:
    """

    # whether a function is propagated, in case of infinite loops
    propagated = {}

    def propagate_once(bv: BinaryView, func: Function, ssa_var: SSAVariable) -> bool:

        propagate = False
        # pointer of a typedef, e.g. SystemTable
        if isinstance(ssa_var.type, PointerType):
            if isinstance(ssa_var.type.target, (NamedTypeReferenceType, StructureType, PointerType)):
                propagate = True

        # typedef of a pointer, e.g. EFI_HANDLE
        elif isinstance(ssa_var.type, NamedTypeReferenceType):
            if isinstance(ssa_var.type.target(bv), PointerType):
                propagate = True

        if not propagate:
            return False

        propagated_name = propagated.get(ssa_var.var.identifier, [])
        if func.start in propagated_name:
            return False

        propagated_name.append(func.start)
        propagated[ssa_var.var.identifier] = propagated_name

        uses = func.hlil.ssa_form.get_ssa_var_uses(ssa_var)
        for use in uses:
            instr = use.parent
            if isinstance(instr, (HighLevelILCallSsa, HighLevelILTailcall)):
                # propagate to sub-function
                if not isinstance(instr.dest, Constant):
                    continue

                sub_func = bv.get_function_at(instr.dest.constant)
                if not sub_func:
                    continue

                sub_func_param_idx = instr.params.index(use)
                # sometimes the identified function parameter number may not align with callsites
                if sub_func_param_idx > len(sub_func.parameter_vars):
                    continue
                type_name = get_type_name(ssa_var.type)
                sub_func.parameter_vars[sub_func_param_idx].type = ssa_var.type
                sub_func.parameter_vars[sub_func_param_idx].name = get_var_name_from_type(type_name)

                # recursive propagate to sub function
                propagate_once(bv, sub_func, SSAVariable(sub_func.parameter_vars[sub_func_param_idx], 0))

            elif isinstance(instr, HighLevelILAssignMemSsa):
                # assignment, define type and add it to list to propagate
                if not isinstance(instr.dest, HighLevelILDerefSsa):
                    continue

                if not isinstance(instr.dest.src, Constant):
                    continue

                type_name = get_type_name(ssa_var.type)
                # this api is a little bit confusing, but here instr.dest is the HighLevelILDerefSsa memory
                # and instr.dest.src is the constant data pointer, so the actual pointing address is
                # instr.dest.src.constant
                var_name = get_var_name_from_type(type_name)
                bv.define_user_data_var(instr.dest.src.constant, ssa_var.type, var_name)
                logger.log_info(
                    f"[propagate_var_type] define {ssa_var.type} {var_name} at {hex(instr.dest.src.constant)}")
                bv.update_analysis_and_wait()

            elif isinstance(instr, HighLevelILDerefFieldSsa):
                # dereferencing field
                expr_type = instr.expr_type
                if not isinstance(expr_type, PointerType):
                    continue
                if not isinstance(expr_type.target, StructureType):
                    continue

                deref_parent = instr.parent
                if isinstance(deref_parent, HighLevelILVarInitSsa):
                    target = deref_parent.dest
                elif isinstance(deref_parent, HighLevelILAssign):
                    if not isinstance(deref_parent.dest, HighLevelILVarSsa):
                        continue
                    target = deref_parent.dest.var
                elif isinstance(deref_parent, HighLevelILAssignMemSsa):
                    # Directly assignment to memory, if assigning to a global variable, propagate directly
                    if not isinstance(deref_parent.dest, HighLevelILDerefSsa):
                        continue
                    target = deref_parent.dest.src
                    if not isinstance(target, Constant):
                        continue

                    name = get_var_name_from_type(str(expr_type.target.registered_name.name))
                    bv.define_user_data_var(target.constant, expr_type, name)
                    logger.log_info(
                        f"[propagate_var_type] define {expr_type} {name} at {hex(target.constant)}")
                    bv.update_analysis_and_wait()
                    continue
                else:
                    continue

                name = get_var_name_from_type(str(expr_type.target.registered_name.name))
                func.create_user_var(target.var, expr_type, name)
                logger.log_info(f"[propagate_var_type] create {expr_type} {name} at {target.var}")
                bv.update_analysis_and_wait()
                propagate_once(bv, func, target)

        return True

    if var in func.hlil.aliased_vars and not func.hlil.ssa_form.get_ssa_var_uses(SSAVariable(var, 0)):
        for ref in func.hlil.get_var_uses(var):
            if isinstance(ref.instr, HighLevelILVarInit):
                # variable passed to an alias
                if not isinstance(ref.instr.ssa_form, HighLevelILVarInitSsa):
                    continue
                alias_var = ref.instr.ssa_form.dest
                propagate_once(bv, func, alias_var)
    else:
        propagate_once(bv, func, SSAVariable(var, 0))


def propagate_type_to_function_callsites(bv: BinaryView, func_addr: int, type_name: str, param_idx: int,
                                         guid_db=None) -> None:
    """
    Propagate the function parameter's type to all it's callsites

    :param: bv: Binary View
    :param: func_addr: int, the start address fo the function
    :param: type_name: str, the type name of the target parameter
    :param: param_idx: int, the index of the target parameter
    :param: guid_db: Optional[Dict], this is for defining the EFI_GUIDs, by default set to None

    :return: None
    """
    callsites = list(bv.get_code_refs(func_addr))
    for callsite in callsites:
        instr = callsite.mlil
        if not isinstance(instr, MediumLevelILCall):
            logger.log_info(
                f"[propagate_type_to_function_callsites] encountered an invalid callsite at {hex(callsite.address)}")
            continue

        params = instr.params
        if len(params) < param_idx + 1:
            logger.log_info(
                f"[propagate_type_to_function_callsites] callsite at {hex(callsite.address)}"
                f"doesn't have a correct param number")
            continue

        # check whether the parameter is a constant address,
        # if so, define data var directly;
        param = params[param_idx]
        if isinstance(param, Constant):
            if bv.get_function_at(param.constant):
                continue
            if type_name == "EFI_GUID" and guid_db:
                lookup_and_define_guid(bv, param.constant, guid_db)
                continue

            sym = bv.get_symbol_at(param.constant)
            if sym:
                name = sym.name
            else:
                name = non_conflicting_variable_name(bv, get_var_name_from_type(type_name))
            bv.define_user_data_var(param.constant, type_name, name)
            logger.log_info(
                f"[propagate_type_to_function_callsites] define {type_name} {name} at {hex(param.constant)}")
            bv.update_analysis_and_wait()

        # check whether is an argument of the parent function, if so recursive define callsites
        elif isinstance(param, MediumLevelILVar):
            # translate to hlil, because hlil will simply the assignments to function arguments
            if not param.hlil:
                continue
            if isinstance(param.hlil, HighLevelILAddressOf):
                if param.hlil.value.type == RegisterValueType.StackFrameOffset:
                    # TODO it's a stack variable, we should be able to parse it
                    pass
            if not isinstance(param.hlil, HighLevelILVar):
                continue
            if not param.hlil.var:
                continue

            func_param_var = param.hlil.var
            if func_param_var.is_parameter_variable:
                parent_function = callsite.function
                parent_param_idx = parent_function.parameter_vars.vars.index(func_param_var)
                # recursive define callsites
                propagate_type_to_function_callsites(bv, parent_function.start, type_name, parent_param_idx, guid_db)


def propagate_type_to_data(bv: BinaryView, type_name: str, name_dict=None, pointer=False, var_name=None,
                           follow_field=False) -> None:
    """
    Find code references of a type and if the reference is a constant pointer pointing to data, define the type there.
    Also supports defining structure types and all its fields

    :param: bv: Binary View
    :param: type_name: str, the type that want to define
    :param: name_dict: Optional[Dict], this is for defining the EFI_GUIDs, by default None
    :param: pointer: bool, whether the type is a pointer or not, by default False
    :param: var_name: str, the default variable name, by default None (and the name will be generated by type name)
    :param: follow_field: bool, when the type is a struct, this flag indicates whether to follow the structure and
            define the fields' types

    :return: None
    """
    if pointer:
        assert follow_field is False
        # these two fields cannot be true at the same time
    refs = list(bv.get_code_refs_for_type(type_name))
    for ref in refs:
        instr = ref.mlil
        if isinstance(instr, MediumLevelILCall):
            if isinstance(instr.dest, MediumLevelILLoadStruct):
                # this is probably a service/protocol call
                if isinstance(instr.dest.expr_type, PointerType):
                    function_type = instr.dest.expr_type.target
                    params = function_type.parameters
                    target_param = None
                    for param in params:
                        if type_name in str(param.type):
                            target_param = params.index(param)
                            break
                    if target_param is None:
                        continue
                    if len(instr.params) < target_param:
                        continue
                    param = instr.params[target_param]
                    if not isinstance(param, MediumLevelILConstPtr):
                        continue

                    var_addr = param.constant
                    data_var = bv.get_data_var_at(var_addr)
                    if data_var:
                        continue
                    if type_name == "EFI_GUID" and name_dict is not None:
                        lookup_and_define_guid(bv, var_addr, name_dict)
                    else:
                        sym = bv.get_symbol_at(var_addr)
                        if not var_name:
                            var_name = non_conflicting_variable_name(bv, get_var_name_from_type(type_name))
                        else:
                            var_name = non_conflicting_variable_name(bv, var_name)

                        if sym is not None:
                            var_name = sym.name

                        if pointer:
                            type_name = type_name + "*"
                        bv.define_user_data_var(var_addr, type_name, var_name)
                        logger.log_info(f"[propagate_type_to_data] define {type_name} {var_name} at {hex(var_addr)}")
                        bv.update_analysis_and_wait()

                        if follow_field:
                            # which means this type is a struct, and it has fields also need to be defined
                            defined_var = bv.get_data_var_at(var_addr)
                            if not isinstance(defined_var.type, NamedTypeReferenceType):
                                continue

                            struct_type = defined_var.type.target(bv)
                            if not isinstance(struct_type, StructureType):
                                continue

                            for field in defined_var.value.keys():
                                field_type = struct_type[field].type
                                field_addr = defined_var.value[field]

                                if not bv.get_segment_at(field_addr):
                                    continue

                                if isinstance(field_type, PointerType):
                                    field_type_name = field_type.target.name
                                elif isinstance(field_type, NamedTypeReferenceType):
                                    if not isinstance(field_type.target(bv), PointerType):
                                        continue
                                    field_type_name = field_type.name
                                else:
                                    continue

                                if field_type_name == "EFI_GUID":
                                    lookup_and_define_guid(bv, field_addr, name_dict)
                                elif "EFI_PEIM_NOTIFY_ENTRY_POINT" in str(field_type_name):
                                    # which means we need to define function type rather than data type
                                    target_func = bv.get_function_at(field_addr)
                                    if not isinstance(field_type, NamedTypeReferenceType):
                                        continue
                                    if not isinstance(field_type.target(bv), PointerType):
                                        continue
                                    func_name = non_conflicting_variable_name(bv, "Notify")
                                    target_func.type = f"EFI_STATUS {func_name}(EFI_PEI_SERVICES **PeiServices, EFI_PEI_NOTIFY_DESCRIPTOR* NotifyDescriptor, VOID* Ppi)"
                                    bv.update_analysis_and_wait()
                                    # also need to propagate type from this entry
                                    for param in target_func.parameter_vars:
                                        propagate_var_type(bv, target_func, param)
                                else:
                                    field_var_name = non_conflicting_variable_name(bv, get_var_name_from_type(
                                        str(field_type_name)))
                                    bv.define_user_data_var(field_addr, field_type, field_var_name)
                                    bv.update_analysis_and_wait()


            else:
                # TODO need to handle wrapper functions, which are calls to constants
                logger.log_info(f"[propagate_type_to_data], got {type_name} passed to function at {hex(ref.address)}]")

        elif isinstance(instr, MediumLevelILSetVar):
            # the ref of type is a variable assignment
            # we don't use mlil to check whether is a parameter, because we may
            # encounter a series of assignment from the args. `mlil.vars_read`
            # can also do that but may need recursive check the assignments
            if not instr.hlil:
                continue
            if isinstance(instr.hlil, HighLevelILVar):
                if not instr.hlil.var:
                    continue
                if instr.hlil.var.is_parameter_variable:
                    # guid is the parameter of the parent function
                    # we should define type for all the callsites
                    parent_param = instr.hlil.var
                    parent_param_idx = ref.function.parameter_vars.vars.index(parent_param)
                    propagate_type_to_function_callsites(bv, ref.function.start, type_name, parent_param_idx, name_dict)
            elif isinstance(instr.hlil, HighLevelILAddressOf):
                # TODO unhandled case
                pass
            elif isinstance(instr.hlil, HighLevelILDeref):
                pass

        else:
            logger.log_info(f"[propagate_type_to_data], got unhandled {type_name} ref at {hex(ref.address)}")
