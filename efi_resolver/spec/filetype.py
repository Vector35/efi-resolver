from enum import Enum


class UEFI_FILE_TYPE(Enum):
    PEIM = 1
    DXE = 2
    FIRMWARE = 3
