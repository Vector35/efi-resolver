"""
This module contains utility functions related to type propagation.
"""

from typing import Optional
from binaryninja import BinaryView
from binaryninja.types import PointerType, NamedTypeReferenceType


def get_type_name(typ) -> Optional[str]:
    """
    input a type object and return the type name
    if the input is a pointer, it will follow the reference and remove the pointer name

    :param typ: the type object to get the name from
    :return: string or None
    """
    if isinstance(typ, PointerType):
        if isinstance(typ.target, NamedTypeReferenceType):
            return str(typ.target.name)
        return str(typ.target).split(" ")[-1]

    if isinstance(typ, NamedTypeReferenceType):
        return str(typ.name)

    # if it's a normal type, no name, return None
    return None


def get_var_name_from_type(name: str) -> str:
    """
    input a type name and return an appropriate variable name, will remove UEFI related prefix and suffix

    :param name:
    :return: str
    """
    name = str(name)
    if name.startswith('EFI_'):
        name = name[4:]

    if name.endswith('_GUID'):
        name = name[:-5]

    words = name.split('_')
    result = "".join(word.capitalize() for word in words)
    return result


def non_conflicting_variable_name(bv: BinaryView, name: str) -> str:
    """
    Input a potential variable name and return a non-conflicting variable name (will add index as suffix)

    :param bv: BinaryView
    :param name: original name
    :return: str
    """
    if not bv.get_symbol_by_raw_name(name):
        return name

    idx = 0
    while True:
        if not bv.get_symbol_by_raw_name(name + "_" + str(idx)):
            return name + "_" + str(idx)
        idx += 1


def lookup_and_define_guid(bv, guid_addr: int, guid_db) -> bool:
    """
    input an address of EFI_GUID, lookup and define the GUID
    :param bv: BinaryView
    :param guid_addr: int, start address of the GUID
    :param guid_db: dict, guid_db (a dictionary from bytes->str)
    :return: bool: whether successfully defined the GUID
    """
    guid = bv.read(guid_addr, 16)
    if not guid or len(guid) < 16:
        return False

    sym = bv.get_symbol_at(guid_addr)
    if sym is not None:
        guid_name = sym.name
    else:
        guid_name = guid_db.get(guid, None)

    if not guid_name:
        guid_name = non_conflicting_variable_name(bv, "UNKNOWN_GUID")

    bv.define_user_data_var(guid_addr, "EFI_GUID", guid_name)
    bv.update_analysis_and_wait()
    return True
