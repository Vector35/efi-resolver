# EFI Resolver Plugin for Binary Ninja

EFI Resolver is a Binary Ninja plugin developed to enhance your UEFI reverse engineering workflow. The plugin automatically resolves type information for EFI protocol usage, making it easier to understand and analyze EFI binaries.

## Features

* **Automatic EFI Protocol Typing**: EFI Resolver intelligently identifies instances where EFI protocols are used and automatically applies the appropriate type information. EFI Resolver looks for references to the boot services protocol functions and applies type information according to the GUID passed to these functions.
* **Global Variable Propagation**: The plugin propagates pointers to the system table, boot services, and runtime services to any global variables where they are stored. This streamlines the process of tracking these vital system components across a binary.
* **Comprehensive UEFI Specification Support**: The plugin fully supports all core protocols within the UEFI specification. However, please note that vendor-specific protocols are not currently supported.

## Usage

To use the EFI Resolver plugin, open a UEFI binary in Binary Ninja. Then, navigate to the `Plugins` menu, and choose `Resolve EFI Protocols`. The plugin will automatically analyze the binary and apply type information.

Please note that this process might take a few moments to complete, depending on the size and complexity of the binary.

## Limitations

The current version of EFI Resolver does not support vendor-specific protocols. It is focused on the core protocols defined within the UEFI specification.

## License

This project is licensed under the terms of the Apache 2.0 license.