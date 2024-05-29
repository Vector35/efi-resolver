from binaryninja import PluginCommand, BinaryView, BackgroundTaskThread
from .efi_resolver import resolve


PluginCommand.register("Resolve UEFI data structures and protocols", "Automatically resolve usage of EFI protocols", resolve)
