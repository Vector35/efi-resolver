# DEPRECATED

The standalone *EFI Resolver* Python plugin is no longer needed, as its functionality has been fully integrated into
Binary Ninja as a built-in workflow starting with version 5.1.7405. This native workflow offers everything the plugin
provided—and more—directly within the core analysis pipeline. The Python plugin is now deprecated and will no longer be
maintained.

The new *EFI Resolver* workflow can be found [here](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/efi_resolver)

# EFI Resolver (v1.3.0)
Author: **Vector 35 Inc**

_A Binary Ninja plugin that automatically resolves type information for EFI protocol usage._

## Description:

EFI Resolver is a Binary Ninja plugin that automates the task of resolving EFI protocol type information. It supports both DXE files and PEI files. It propagates parameter pointers from entry points to system table, MM system table, boot services, and runtime services to any global variables where they are stored. For PEI files, it also support identifying [processor-specific mechanisms](https://uefi.org/specs/PI/1.8/V1_PEI_Foundation.html#pei-services-table-retrieval) for retrieving PEI services pointers. The plugin also identifies references to the boot services, MM protocol functions and PEI services, and applies type information according to the GUID passed to these functions. The plugin supports the core UEFI specification, but does not support vendor protocols.

## Installation Instructions

### Darwin

no special instructions, package manager is recommended

### Linux

no special instructions, package manager is recommended

### Windows

no special instructions, package manager is recommended

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 4333

## Required Dependencies

The following dependencies are required for this plugin:

## License

This plugin is released under a Apache-2.0 license.
## Metadata Version

3

## Supplying Custom UEFI Protocol GUIDs and Types

By default EFI Resolver propagates types and GUIDs using Binary Ninja's native platform types for EFI. Many UEFI
firmware binaries include types (and GUIDs) for proprietary protocols. This section describes how users can supply
custom UEFI types and GUIDs for use with EFI Resolver type propagation.

### User-supplied EFI GUIDs

EFI Resolver uses a JSON file to associate user-supplied EFI GUIDs with types for propagation. GUIDs for proprietary
protocol types can be used with EFI Resolver by creating a file at `<user folder>/types/efi-guids.json` containing JSON
entries in the following format:

```json
{
  "EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID": [
    19088743,
    35243,
    52719,
    1,
    35,
    69,
    103,
    137,
    171,
    205,
    239
 ]
}
```

In this example, the protocol type of `EFI_EXAMPLE_CUSTOM_PROTOCOL` is mapped to the
`{0x01234567,0x89ab,0xcdef,{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}}` GUID (named `EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID`).
To test that the file is a valid JSON file, run `python -m json.tool < efi-guids.json`.

__Note: user-supplied propretary GUIDs from `efi-guids.json` are used to name variables regardless of whether or not an associated platform type has been loaded. If EFI Resolver fails to query the type for an EFI protocol interface, it will set the variable type for the protocol interface pointer to `VOID*`.__

### User-supplied EFI Platform Types

Types and structures for proprietary protocols are to be imported using Binary Ninja's standard mechanism for loading
user-supplied platform types. Instructions on adding custom platform types can be found [here](https://docs.binary.ninja/guide/types/platformtypes.html). Available EFI platform names include:
- `efi-x86`
- `efi-x86_64`
- `efi-thumb2`
- `efi-armv7`
- `efi-aarch64`
- `efi-windows-aarch64`
- `efi-windows-x86`
- `efi-windows-x86_64`

To avoid having to add duplicate types in each platform-specific `*.c` file, it is recommended to add common types
to a top-level `efi.c` file and `#include` the file in the platform-specific `*.c` files. For example:

```C
// <user folder>/types/platform/efi-x86_64.c including <user folder>/types/efi.c
#include "../efi.c"
```

To test that C source files containing custom EFI platform types are in the correct format, use the `bv.platform.parse_types_from_source_file` API.

Alternatively, user types can be supplied manually from type libraries, header files, or any other mechanism supported
by Binary Ninja. Just ensure that the name for types associated with GUIDs match what is in `efi-guids.json`. Protocol
GUID names in `efi-guids.json` should end with `_PROTOCOL_GUID` and the prefix must be identical to the associated
protocol type name. For example, if the GUID is named `EFI_EXAMPLE_PROTOCOL_GUID`, EFI Resolver will attempt to
lookup a type named `EFI_EXAMPLE_PROTOCOL`.

### Full Example

In summary, including a custom platform type of `EFI_EXAMPLE_CUSTOM_PROTOCOL` for the `efi-x86` platform and associating
it with a GUID named `EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID` requires two steps:

1. Create the `<user folder>/types/platform/efi-x86.c` header file:

```C
struct EFI_EXAMPLE_CUSTOM_PROTOCOL
{
    uint32_t length;
}
```

2. Create the `<user folder>/types/efi-guids.json` file:

```json
{
    "EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID": [
      19088743,
      35243,
      52719,
      1,
      35,
      69,
      103,
      137,
      171,
      205,
      239
    ]
}
```

After a Binary Ninja restart, when a binary is loaded with the `efi-x86` platform, the `EFI_EXAMPLE_CUSTOM_PROTOCOL`
type will be imported. When EFI Resolver runs, it will detect uses of `EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID` and propagate
the `EFI_EXAMPLE_CUSTOM_PROTOCOL` type.
