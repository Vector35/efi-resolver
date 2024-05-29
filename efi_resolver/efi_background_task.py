from binaryninja import BackgroundTaskThread, BinaryView
from .spec import UEFI_FILE_TYPE
from .util import EfiGuidDataRenderer
from .efi_resolver import EfiResolver


class EfiBackgroundTask(BackgroundTaskThread, EfiResolver):
    """
    Background task that analyze UEFI driver/firmware
    The core analysis methods are implemented in EfiResolver, so that we can create an EfiResolver object and
    analyze the binary in command line.
    """

    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, '', False)
        EfiResolver.__init__(self, bv)

    def run(self):
        """
        Run Uefi Resolver in the background
        """
        EfiGuidDataRenderer().register_type_specific()
        self._fix_seg_privileges()
        if self.cancelled:
            return

        # Define entry type according to file type
        if self.bv.get_view_of_type("PE"):
            filetype = UEFI_FILE_TYPE.DXE
        elif self.bv.get_view_of_type("TE"):
            filetype = UEFI_FILE_TYPE.PEIM
        else:
            filetype = UEFI_FILE_TYPE.FIRMWARE
        self.progress = "Setting EntryPoint type ..."
        self._set_entry_point(filetype)
        if self.cancelled:
            return

        # mark gImageHandle, gST, gRT, gBS, gSmst
        self.progress = "Propagating global structures..."
        self._propagate_types_from_entry()
        if self.cancelled:
            return
        # set types of windows bootloader pointers
        self.progress = "Setting windows bootloader pointers' type ..."
        self._set_windows_bootloader_type()
        if self.cancelled:
            return

        if self.filetype == UEFI_FILE_TYPE.DXE:
            self.progress = "Found DXE file, Resolving DXE protocols..."
            self._resolve_dxe_protocols()
        elif self.filetype == UEFI_FILE_TYPE.PEIM:
            self.progress = "Found PEI file, Resolving PPIs..."
            self._resolve_ppis()
        if self.cancelled:
            return

        self.progress = "Resolving SMM protocols..."
        self._resolve_mm_protocols()
        if self.cancelled:
            return

        self.progress = "Resolving EFI_GUID data variables..."
        self._resolve_guid_data()
