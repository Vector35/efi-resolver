protocol_binding_services = {
    # 0x80: {"name": "InstallProtocolInterface", "guid": 1, "interface": 3},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_INSTALL_PROTOCOL_INTERFACE)(
    #   IN OUT EFI_HANDLE               *Handle,
    #   IN     EFI_GUID                 *Protocol,
    #   IN     EFI_INTERFACE_TYPE       InterfaceType,
    #   IN     VOID                     *Interface
    #   );

    # 0x88: {"name": "ReinstallProtocolInterface", "guid": 1, "interface": 3},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_REINSTALL_PROTOCOL_INTERFACE)(
    #   IN EFI_HANDLE               Handle,
    #   IN EFI_GUID                 *Protocol,
    #   IN VOID                     *OldInterface,
    #   IN VOID                     *NewInterface
    #   );

    # 0x90: {"name": "UninstallProtocolInterface", "guid": 1, "interface": 2},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_UNINSTALL_PROTOCOL_INTERFACE)(
    #   IN EFI_HANDLE               Handle,
    #   IN EFI_GUID                 *Protocol,
    #   IN VOID                     *Interface
    #   );

    0x98: {"name": "HandleProtocol", "guid": 1, "interface": 2},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_HANDLE_PROTOCOL)(
    #   IN  EFI_HANDLE               Handle,
    #   IN  EFI_GUID                 *Protocol,
    #   OUT VOID                     **Interface
    #   );

    0x118: {"name": "OpenProtocol", "guid": 1, "interface": 2},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_OPEN_PROTOCOL)(
    #   IN  EFI_HANDLE                Handle,
    #   IN  EFI_GUID                  *Protocol,
    #   OUT VOID                      **Interface  OPTIONAL,
    #   IN  EFI_HANDLE                AgentHandle,
    #   IN  EFI_HANDLE                ControllerHandle,
    #   IN  UINT32                    Attributes
    #   );

    0x140: {"name": "LocateProtocol", "guid": 0, "interface": 2},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_LOCATE_PROTOCOL)(
    #   IN  EFI_GUID  *Protocol,
    #   IN  VOID      *Registration  OPTIONAL,
    #   OUT VOID      **Interface
    #   );

    # TODO multiple protocol interfaces install not supported yet
    # 0x148: {"name": "InstallMultipleProtocolInterfaces"},
    # 0x150: {"name": "UninstallMultipleProtocolInterfaces"},
}

variable_services = {
    0x48: {"name": "GetVariable", "guid": 1, "variable": 0},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_GET_VARIABLE)(
    #   IN     CHAR16                      *VariableName,
    #   IN     EFI_GUID                    *VendorGuid,
    #   OUT    UINT32                      *Attributes     OPTIONAL,
    #   IN OUT UINTN                       *DataSize,
    #   OUT    VOID                        *Data           OPTIONAL
    #   );
    0x50: {"name": "GetNextVariableName", "guid": 2, "variable": 1},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_GET_NEXT_VARIABLE_NAME)(
    #   IN OUT UINTN                    *VariableNameSize,
    #   IN OUT CHAR16                   *VariableName,
    #   IN OUT EFI_GUID                 *VendorGuid
    #   );

    0x58: {"name": "SetVariable", "guid": 1, "variable": 0},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_SET_VARIABLE)(
    #   IN  CHAR16                       *VariableName,
    #   IN  EFI_GUID                     *VendorGuid,
    #   IN  UINT32                       Attributes,
    #   IN  UINTN                        DataSize,
    #   IN  VOID                         *Data
    #   );

    # TODO not support yet
    # 0x80: {"name": "QueryVariableInfo"},
    # typedef
    # EFI_STATUS
    # (EFIAPI *EFI_QUERY_VARIABLE_INFO)(
    #   IN  UINT32            Attributes,
    #   OUT UINT64            *MaximumVariableStorageSize,
    #   OUT UINT64            *RemainingVariableStorageSize,
    #   OUT UINT64            *MaximumVariableSize
    #   );
}

pei_ppi_services = {
    # 0x18: {"name": "InstallPpi", "descriptor": 1},
    # 0x20: {"name": "ReinstallPpi", "descriptor": 2},
    0x20: {"name": "LocatePpi", "guid": 1, "interface": 4},
    # 0x30: {"name": "NotifyPpi", "descriptor": 1}
}
