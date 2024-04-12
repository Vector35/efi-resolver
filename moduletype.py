from enum import Enum
from binaryninja import BinaryView, SymbolType


class EFIModuleType(Enum):
    """UEFI module types"""

    UNKNOWN = 0
    DXE = 1
    PEI = 2


def set_efi_module_entry_type(bv: BinaryView, modtype: EFIModuleType) -> None:
    """Set the prototype for the module entrypoint"""

    _start = bv.get_symbol_by_raw_name("_start")
    if not _start or _start.type != SymbolType.FunctionSymbol:
        return

    func = bv.get_function_at(_start.address)
    if not func:
        return

    if modtype == EFIModuleType.PEI:
        func.type = "EFI_STATUS _start(EFI_PEI_FILE_HANDLE FileHandle, EFI_PEI_SERVICES **PeiServices)"

    if modtype == EFIModuleType.DXE:
        func.type = "EFI_STATUS _start(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)"

    func.reanalyze()


def identify_efi_module_type(bv: BinaryView) -> EFIModuleType:
    """Identify the type of EFI module

    PE's are reported as DXE modules and TE's are reported as PEI modules. This is correct for most
    cases, and is the convention used by most UEFI tooling.
    """

    if bv.get_view_of_type("PE"):
        return EFIModuleType.DXE

    if bv.get_view_of_type("TE"):
        return EFIModuleType.PEI

    return EFIModuleType.UNKNOWN
