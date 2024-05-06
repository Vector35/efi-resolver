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

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 4333

## Required Dependencies

The following dependencies are required for this plugin:

## License

This plugin is released under a Apache-2.0 license.
## Metadata Version

2
