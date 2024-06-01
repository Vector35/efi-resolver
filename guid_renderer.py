from binaryninja import DataRenderer, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenType, BinaryReader


class EfiGuidDataRenderer(DataRenderer):
    """
    DataRenderer for displaying EFI_GUID in a more human-readable manner.
    """
    def __init__(self):
        DataRenderer.__init__(self)

    def perform_is_valid_for_data(self, ctxt, view, addr, typ, context):
        return DataRenderer.is_type_of_struct_name(typ, "EFI_GUID", context)

    def perform_get_lines_for_data(self, ctxt, view, addr, typ, prefix, width, context):
        result = [DisassemblyTextLine(prefix, addr)]
        reader = BinaryReader(view)
        reader.seek(addr)
        data1 = reader.read32()
        data2 = reader.read16()
        data3 = reader.read16()
        data4 = reader.read64be()
        guid_str = f"{data1:08x}-{data2:04x}-{data3:04x}-{data4:016x}"
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, "  [EFI_GUID(\""),
                  InstructionTextToken(InstructionTextTokenType.StringToken, guid_str),
                  InstructionTextToken(InstructionTextTokenType.TextToken, "\")]")]

        result.append(DisassemblyTextLine(tokens, addr))
        return result

    def __del__(self):
        pass
