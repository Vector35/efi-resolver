# EFI Resolver (v1.1.0)
Author: **Vector 35 Inc**

_A Binary Ninja plugin that automatically resolves type information for EFI protocol usage._

## Description:

EFI Resolver is a Binary Ninja plugin that automates the task of resolving EFI protocol type information. It propagates pointers to system table, MM system table, boot services, and runtime services to any global variables where they are stored. The plugin also identifies references to the boot services and MM protocol functions and applies type information according to the GUID passed to these functions. The plugin supports the core UEFI specification, but does not support vendor protocols.

## Installation Instructions

### Darwin

no special instructions, package manager is recommended

### Linux

no special instructions, package manager is recommended

### Windows

no special instructions, package manager is recommended

## Instructions on Adding Custom Protocols

efi-resolver uses a `json` file to maintain the mapping between GUID and names.

If you want to add a custom protocol binding, you will need to put the guid inside the `<user folder>/types/efi-guids.json`
and (optional) add your custom types to [user platform types](https://docs.binary.ninja/guide/index.html#user-folder).

If you only add GUIDs, the protocol interfaces will be set to `VOID*` by default.

### File Path

Custom types should be placed inside the [user platform folder](https://docs.binary.ninja/guide/index.html#user-folder).
And the filename should be `<platform name>.c`, available names:

Available efi platform names:
- `efi-x86`
- `efi-x86_64`
- `efi-thumb2`
- `efi-armv7`
- `efi-aarch64`
- `efi-windows-aarch64`
- `efi-windows-x86`
- `efi-windows-x86_64`

You may not want to add the same types multiple times for each platform.
One possible way is to add a `efi.c` in `<user folder>/types` and include this file in each platform types.
Just like the way you write C programs.

For example,
```C
// efi-x86_64.c
#include "../efi.c"
```

### File Format

#### C file's format

There is no format requirements for `.c` file, but you need to make sure it follows C syntax and can be parsed correctly.

You can test it in binja's python console with

```python
bv.platform.parse_types_from_source_file
```

#### Json format

The content of `efi-guids.json` should be a dictionaries, mapping from names to GUID content. We follows the pattern of 
[guiddb](https://github.com/binarly-io/guiddb). Each GUID should be represented as a list of numbers. 

This json file should be loadable by `json.load`.
```python
import json
with open(os.path.join(user_directory(), 'types', 'efi-guids.json'), 'r') as f:
    mappings = json.load(f)
```

### Naming

The guid names are defined in `efi-guids.json`, and the types are defined in `types/platform` folder.
To connect the guid name with type correctly, you need to make sure the names follows the pattern in specification.

A protocol's guid should ends with `_PROTOCOL_GUID`, and it should have the same prefix with the related protocol name.

If you add a protocol interface type, `EFI_EXAMPLE_PROTOCOL`, the corresponding GUID should has a name 
`EFI_EXAMPLE_PROTOCOL_GUID`. 

### Example

Here is an example (all these files are inside the user folder)

In `types/platform/efi-x86.c`
```C
#include "../efi.c"
```

In `types/efi.c`
```c
struct EFI_EXAMPLE_CUSTOM_PROTOCOL
{
    uint32_t length;
}
```

In `types/efi-protocol.json`
```
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

This binds a protocol called `EFI_EXAMPLE_CUSTOM_PROTOCOL`, and has GUID 
`{0x01234567,0x89ab,0xcdef,{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}}`
(in edk2 format)


## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 4333

## Required Dependencies

The following dependencies are required for this plugin:

## License

This plugin is released under a Apache-2.0 license.
## Metadata Version

2
