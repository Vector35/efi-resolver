"""
This module contains utility functions (renaming, defining types etc.)
"""
from binaryninja import PointerType, NamedTypeReferenceType, Function, BinaryView, Type, StructureType, StructureVariant


def get_type_name(typ: Type) -> str:
    """
    Input a type and return a type name, if it's a pointer, return the pointed name
    if it's a named type reference, return the original name
    """
    if isinstance(typ, PointerType):
        if isinstance(typ.target, NamedTypeReferenceType):
            return str(typ.target.name)
        return str(typ.target).split(" ")[-1]

    if isinstance(typ, NamedTypeReferenceType):
        return str(typ.name)


def non_conflicting_local_variable_name(func: Function, base_name: str) -> str:
    """
    Input a function and a potential variable name, and return a non-conflicting local variable name.
    """
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
        name = f"{base_name}{idx}"
    return name


def non_conflicting_symbol_name(bv: BinaryView, base_name: str) -> str:
    """
    Input a potential symbol name(function name, data variable name etc.) and return a non-conflicting symbol name
    """
    idx = 0
    while True:
        name = f"{base_name}{idx}"
        if bv.get_symbol_by_raw_name(name):
            idx += 1
        else:
            break
    return name


def remove_type_prefix_suffix(type_name: str) -> str:
    """
    Input a type name and return a type name with all prefix modifiers and suffix stars removed.
    """
    if type_name.endswith("*"):
        type_name = type_name.rstrip("*")
    if " " in type_name:
        type_name = type_name.split(" ")[-1]
    return type_name


def get_var_name_from_type(type_name: str) -> str:
    """
    Input a type name and return an appropriate variable name. (in pascalcase style)
    If it's an UEFI related name, remove the `EFI` prefix and `GUID`, `PROTOCOL` suffix
    """
    if type_name.startswith("Unknown"):
        return type_name
    name = type_name
    if name.startswith("EFI_"):
        name = name[4:]
    if name.endswith("_GUID"):
        name = name[:-5]
    if name.endswith("_PROTOCOL"):
        name = name[:-9]

    return "".join([word.capitalize() for word in name.split("_")])


def get_type(bv, type_name):
    """
    Input a type string and try to get type from binary view and platform types
    return None if there is no such type
    """
    _type = bv.types.get(type_name)
    if _type != None:
        return _type
    return bv.platform.types.get(type_name)


def non_conflicting_type_name(bv:BinaryView, basename: str):
    """ input a basename and return a non-conflicting type name """
    idx = 0
    while True:
        name = f"{basename}{idx}"
        if get_type(bv, name):
            idx += 1
        else:
            break
    return name


def create_struct(bv: BinaryView, guid_name: str):
    """ Create an empty struct according to input guid name """
    empty_struct = StructureType.create(None, True, StructureVariant.StructStructureType, bv.platform, 0)
    if guid_name.startswith("Unknown"):
        # We don't need to use `non_conflicting` here, because the guid name should be non_conflicting
        # simply replace the "Guid" substr so that they share the same suffix index
        name = guid_name.replace("Guid", "")
        bv.define_user_type(name, empty_struct)
    else:
        # check whether this protocol type has been defined
        name = guid_name.replace("_GUID", "")
        if not bv.user_type_container.get_type_by_name(name):
            bv.define_user_type(name, empty_struct)
    return name