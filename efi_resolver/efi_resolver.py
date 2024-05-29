import json
import os
import struct
import sys
from pathlib import Path
from binaryninja import BinaryView, SegmentFlag, SectionSemantics, bundled_plugin_path
from .spec import UEFI_FILE_TYPE
from .type import propagate_var_type, resolve_protocols, propagate_type_to_data, resolve_mm_protocols, resolve_ppis
from .util import logger


class EfiResolver:
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.filetype = None
        self.gBS = []
        self.gRT = []
        self.guid_db = None
        self._init_guid_db()
        self.protocol_db = None
        self._init_protocol_db()

    def _init_guid_db(self) -> None:
        """Open Binarly's guiddb.json and return a dictionary of GUIDs"""

        current_dir = Path(__file__).parent.resolve()
        guid_db_path = os.path.join(current_dir, "guiddb/guids.json")
        with open(guid_db_path, "r", encoding="utf-8") as f:
            guid_db = json.load(f)

        guids = {}
        for guid_name, guid in guid_db.items():
            guids[(
                    guid[0].to_bytes(4, "little")
                    + guid[1].to_bytes(2, "little")
                    + guid[2].to_bytes(2, "little")
                    + guid[3].to_bytes(1, "little")
                    + guid[4].to_bytes(1, "little")
                    + guid[5].to_bytes(1, "little")
                    + guid[6].to_bytes(1, "little")
                    + guid[7].to_bytes(1, "little")
                    + guid[8].to_bytes(1, "little")
                    + guid[9].to_bytes(1, "little")
                    + guid[10].to_bytes(1, "little")
            )] = guid_name

        self.guid_db = guids

    def _init_protocol_db(self) -> None:
        """ read built-in efi.c and parse protocol structures"""
        if sys.platform == "darwin":
            efi_def_path = os.path.join(bundled_plugin_path(), "..", "..", "Resources", "types", "efi.c")
        else:
            efi_def_path = os.path.join(bundled_plugin_path(), "..", "types", "efi.c")

        try:
            efi_defs = open(efi_def_path, "r", encoding="utf-8").readlines()
        except FileNotFoundError:
            logger.log_alert(
                f"Could not open EFI type definition file at '{efi_def_path}'. Your version of Binary Ninja may be out of date. Please update to version 3.5.4331 or higher.")
            return

        protocols = {}
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
        self.protocol_db = protocols

    def _set_entry_point(self, filetype) -> None:
        """
        Set the type of ModuleEntry according to the filetype
        """
        self.filetype = filetype
        match filetype:
            case UEFI_FILE_TYPE.DXE:
                self.bv.entry_function.type = "EFI_STATUS _ModuleEntryPoint(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)"

            case UEFI_FILE_TYPE.PEIM:
                self.bv.entry_function.type = "EFI_STATUS _ModuleEntryPoint(EFI_PEI_FILE_HANDLE FileHandle, EFI_PEI_SERVICES **PeiServices)"

            case UEFI_FILE_TYPE.FIRMWARE:
                logger.log_alert("Analysis on entire firmware is not supported yet")

        self.bv.update_analysis_and_wait()

    def _fix_seg_privileges(self) -> None:
        """
        Make segments and section readable and writable
        """
        for seg in self.bv.segments:
            self.bv.add_user_segment(seg.start, seg.data_length, seg.data_offset, seg.data_length,
                                     SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)

            for section in self.bv.get_sections_at(seg.start):
                self.bv.add_user_section(section.name, section.end - section.start,
                                         SectionSemantics.ReadWriteDataSectionSemantics)

    def _propagate_types_from_entry(self) -> None:
        """
        Propagate types from entry
        """
        func = self.bv.entry_function
        for param in self.bv.entry_function.parameter_vars:
            propagate_var_type(self.bv, func, param)

    def _set_windows_bootloader_type(self) -> None:
        """
        Set types of known windows bootloader pointers
        """
        sym = self.bv.get_symbol_by_raw_name("EfiST")
        if sym is not None:
            self.bv.define_user_data_var(sym.address, "EFI_SYSTEM_TABLE*", "EfiST")
        sym = self.bv.get_symbol_by_raw_name("EfiBS")
        if sym is not None:
            self.bv.define_user_data_var(sym.address, "EFI_BOOT_SERVICES*", "EfiBS")
        sym = self.bv.get_symbol_by_raw_name("EfiRT")
        if sym is not None:
            self.bv.define_user_data_var(sym.address, "EFI_RUNTIME_SERVICES*", "EfiRT")
        sym = self.bv.get_symbol_by_raw_name("EfiConOut")
        if sym is not None:
            self.bv.define_user_data_var(sym.address, "EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*", "EfiConOut")
        sym = self.bv.get_symbol_by_raw_name("EfiConIn")
        if sym is not None:
            self.bv.define_user_data_var(sym.address, "EFI_SIMPLE_TEXT_INPUT_PROTOCOL*", "EfiConIn")

        self.bv.update_analysis_and_wait()

    def _resolve_dxe_protocols(self):
        """
        resolve DXE protocols, at this point, the gBS pointers and gRT pointers should be analyzed
        """
        self.gBS = self.bv.get_symbols_by_raw_name("BootServices")
        self.gRT = self.bv.get_symbols_by_raw_name("RuntimeServices")

        # we could use the references of gBS, but if the type is correctly applied, we should be able to find all
        # references by using `get_code_refs_for_type`

        resolve_protocols(self.bv, self.protocol_db, self.guid_db)
        # TODO add protocol information into summary

    def _resolve_ppis(self):
        """
        resolve PPIs, this would define the descriptors and then analyze `LocatePpi`
        """
        resolve_ppis(self.bv, self.protocol_db, self.guid_db)
        # TODO add protocol information into summary

    def _resolve_guid_data(self):
        """
        Analyze all references to `EFI_GUID` and if it's a function parameter, analyze the callsites
        """
        propagate_type_to_data(self.bv, "EFI_GUID", self.guid_db)
        # TODO add items into guid_usage

    def _resolve_mm_protocols(self):
        """
        resolve SMM/MM related protocols
        """
        resolve_mm_protocols(self.bv, self.protocol_db, self.guid_db)
        # TODO add protocol information into summary
