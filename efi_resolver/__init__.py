from binaryninja import BinaryView
from .spec import UEFI_FILE_TYPE
from .efi_resolver import EfiResolver
from .efi_background_task import EfiBackgroundTask


def resolve(bv: BinaryView):
    task = EfiBackgroundTask(bv)
    task.start()
