from binaryninja import PluginCommand, BinaryView, BackgroundTaskThread, log_alert
from .moduletype import identify_efi_module_type, set_efi_module_entry_type, EFIModuleType
from .protocols import (
    init_protocol_mapping,
    define_handle_protocol_types,
    define_open_protocol_types,
    define_locate_protocol_types,
    define_locate_mm_system_table_types,
    define_locate_smm_system_table_types,
    define_mm_locate_protocol_types,
    define_smm_locate_protocol_types,
    define_mm_handle_protocol_types,
    define_smm_handle_protocol_types
)

from .system_table import propagate_system_table_pointers
from .guid_renderer import EfiGuidDataRenderer

def resolve_efi(bv: BinaryView):
    class Task(BackgroundTaskThread):
        def __init__(self, bv: BinaryView):
            super().__init__("Initializing EFI protocol mappings...", True)
            self.bv = bv

        def _resolve_dxe(self):
            self.progress = "Propagating EFI system table pointers..."
            if not propagate_system_table_pointers(self.bv, self):
                return

            self.progress = "Defining types for uses of HandleProtocol..."
            if not define_handle_protocol_types(self.bv, self):
                return

            self.progress = "Defining types for uses of OpenProtocol..."
            if not define_open_protocol_types(self.bv, self):
                return

            self.progress = "Defining types for uses of LocateProtocol..."
            if not define_locate_protocol_types(self.bv, self):
                return

            # SMM/MM types cannot be propagated until EFI_BOOT_SERVICES types are propagated and the
            # EFI_MM_BASE_PROTOCOL or EFI_SMM_BASE2_PROTOCOL is resolved
            if "EFI_MM_SYSTEM_TABLE" in self.bv.types:
                self.progress = "Defining types for SMM/MM system tables..."
                if not define_locate_mm_system_table_types(self.bv, self) or not define_locate_smm_system_table_types(
                    self.bv, self
                ):
                    return

                self.progress = "Defining types for uses of SMM/MM LocateProtocol..."
                if not define_mm_locate_protocol_types(self.bv, self) or not define_smm_locate_protocol_types(
                    self.bv, self
                ):
                    return

                self.progress = "Defining types for uses of SMM/MM HandleProtocol..."
                if not define_mm_handle_protocol_types(self.bv, self) or not define_smm_handle_protocol_types(
                    self.bv, self
                ):
                    return

        def run(self):
            if not init_protocol_mapping():
                return

            if "EFI_SYSTEM_TABLE" not in self.bv.types:
                log_alert("This binary is not using the EFI platform. Use Open with Options when loading the binary to select the EFI platform.")
                return

            module_type = identify_efi_module_type(self.bv)
            if module_type == EFIModuleType.UNKNOWN:
                log_alert("Could not identify the EFI module type.")
                return

            self.bv.begin_undo_actions()
            EfiGuidDataRenderer().register_type_specific()
            try:
                try:
                    set_efi_module_entry_type(self.bv, module_type)
                except SyntaxError:
                    log_alert("Failed to set entry function type. Update Binary Ninja for latest EFI type definitions.")
                    return

                if module_type == EFIModuleType.DXE:
                    self._resolve_dxe()
                elif module_type == EFIModuleType.PEI:
                    log_alert("TE PEI modules are not yet supported.")
            finally:
                self.bv.commit_undo_actions()

    Task(bv).start()

PluginCommand.register("Resolve EFI Protocols", "Automatically resolve usage of EFI protocols", resolve_efi)
