#include "Resolver.h"

string Resolver::nonConflictingName(const string basename)
{
    int idx = 0;
    string name = basename;
    do {
        auto sym = m_view->GetSymbolByRawName(name);
        if (!sym)
            return name;
        else {
            name = basename + to_string(idx);
            idx += 1;
        }
    } while (true);
}

string Resolver::nonConflictingLocalName(Ref<Function> func, const string basename)
{
    string name = basename;
    int idx = 0;
    while (true) {
        bool ok = true;
        for (auto var_pair : func->GetVariables()) {
            if (var_pair.second.name == name) {
                ok = false;
                break;
            }
        }
        if (ok)
            break;
        name = basename + to_string(idx);
        idx += 1;
    }
    return name;
}

static string GetBundledEfiPath()
{
    string path = GetBundledPluginDirectory();
#if defined(_WIN32)
    return path + "..\\types\\efi.c";
#elif defined(_linux__)
    return path + "../types/efi.c";
#else
    return path + "/../../Resources/types/efi.c";
#endif
}

static string GetUserGuidPath()
{
    string path = GetUserDirectory();
#if defined(_WIN32)
    return path + "\\types\\efi-guids.json";
#elif defined(_linux__)
    return path + "/types/efi-guids.json";
#else
    return path + "/types/efi-guids.json";
#endif
}

static EFI_GUID parseGuid(const string& guid_str)
{
    EFI_GUID guid;
    istringstream iss(guid_str);
    string token;
    long value;

    getline(iss, token, ',');
    value = stoul(token, nullptr, 16);
    guid[0] = static_cast<uint8_t>(value);
    guid[1] = static_cast<uint8_t>(value >> 8);
    guid[2] = static_cast<uint8_t>(value >> 16);
    guid[3] = static_cast<uint8_t>(value >> 24);

    getline(iss, token, ',');
    value = stoul(token, nullptr, 16);
    guid[4] = static_cast<uint8_t>(value);
    guid[5] = static_cast<uint8_t>(value >> 8);

    getline(iss, token, ',');
    value = stoul(token, nullptr, 16);
    guid[6] = static_cast<uint8_t>(value);
    guid[7] = static_cast<uint8_t>(value >> 8);

    for (int i = 8; i < 16; i++) {
        getline(iss, token, ',');
        value = stoul(token, nullptr, 16);
        guid[i] = static_cast<uint8_t>(value);
    }
    return guid;
}

bool Resolver::parseProtocolMapping(const string filePath)
{
    vector<pair<EFI_GUID, string>> guids;
    ifstream efi_defs;
    string line;

    m_protocol.clear();

    efi_defs.open(filePath.c_str());
    if (!efi_defs.is_open())
        return false;

    while (getline(efi_defs, line)) {
        if (line.substr(0, 12) == "///@protocol") {
            string guid = line.substr(12);
            guid.erase(remove_if(guid.begin(), guid.end(), [](char c) { return c == '{' || c == '}' || c == ' '; }), guid.end());
            guids.push_back({ parseGuid(guid), "" });
        } else if (line.substr(0, 11) == "///@binding") {
            istringstream iss(line.substr(11));
            string guid_name, guid;
            iss >> guid_name >> guid;
            guid.erase(remove_if(guid.begin(), guid.end(), [](char c) { return c == '{' || c == '}' || c == ' '; }), guid.end());
            guids.push_back({ parseGuid(guid), guid_name });
        } else if (line.substr(0, 6) == "struct") {
            if (guids.empty())
                continue;
            istringstream iss(line.substr(6));
            string name;
            iss >> name;
            for (const auto& guid_info : guids) {
                if (guid_info.second.empty()) {
                    m_protocol[guid_info.first] = make_pair(name, name + "_GUID");
                } else {
                    m_protocol[guid_info.first] = make_pair(name, guid_info.second);
                }
            }
        } else {
            guids.clear();
        }
    }
    efi_defs.close();

    return true;
}

bool Resolver::parseUserGuidIfExists(const string filePath)
{
    ifstream user_json(filePath);
    if (!user_json.is_open())
        return false;

    nlohmann::json json_content;
    user_json >> json_content;

    for (auto element : json_content.items()) {
        auto guidName = element.key();
        auto guidBytes = element.value();
        if (guidBytes.size() != 11) {
            LogError("Error: GUID array size is incorrect for %s", guidName.c_str());
            return false;
        }
        EFI_GUID guid;
        guid[0] = static_cast<uint8_t>(int(guidBytes[0]));
        guid[1] = static_cast<uint8_t>(int(guidBytes[0]) >> 8);
        guid[2] = static_cast<uint8_t>(int(guidBytes[0]) >> 16);
        guid[3] = static_cast<uint8_t>(int(guidBytes[0]) >> 24);

        guid[4] = static_cast<uint8_t>(int(guidBytes[1]));
        guid[5] = static_cast<uint8_t>(int(guidBytes[1]) >> 8);

        guid[6] = static_cast<uint8_t>(int(guidBytes[2]));
        guid[7] = static_cast<uint8_t>(int(guidBytes[2]) >> 8);

        guid[8] = static_cast<uint8_t>(int(guidBytes[3]));
        guid[9] = static_cast<uint8_t>(int(guidBytes[4]));
        guid[10] = static_cast<uint8_t>(int(guidBytes[5]));
        guid[11] = static_cast<uint8_t>(int(guidBytes[6]));
        guid[12] = static_cast<uint8_t>(int(guidBytes[7]));
        guid[13] = static_cast<uint8_t>(int(guidBytes[8]));
        guid[14] = static_cast<uint8_t>(int(guidBytes[9]));
        guid[15] = static_cast<uint8_t>(int(guidBytes[10]));

        // Insert the GUID and its name into the map
        m_user_guids[guid] = guidName;
    }

    return true;
}

void Resolver::initProtocolMapping()
{
    if (!m_protocol.empty())
        return;
    auto fileName = GetBundledEfiPath();
    if (!parseProtocolMapping(fileName))
        LogAlert("Binary Ninja Version Too Low. Please upgrade to a new version.");

    fileName = GetUserGuidPath();
    parseUserGuidIfExists(fileName);
}

bool Resolver::setModuleEntry(EFIModuleType fileType)
{
    // Wait until initial analysis is finished
    m_view->UpdateAnalysisAndWait();

    uint64_t entry = m_view->GetEntryPoint();
    auto entryFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), entry);
    if (!entryFunc)
    {
        LogDebug("Entry func Not found... ");
        return false;
    }

    // TODO sometimes the parameter at callsite cannot be correctly recognized, #Vector35/binaryninja-api/4529
    //     temporary workaround for this issue, adjust callsite types in entry function if it doesn't has parameters

    // Note: we only adjust the callsite in entry function, this is just a temp fix and it cannot cover all cases
    auto callsites = entryFunc->GetCallSites();
    LogDebug("Checking callsites at 0x%llx", entryFunc->GetStart());
    LogDebug("callsite count : %zu", callsites.size());
    for (auto callsite: entryFunc->GetCallSites())
    {
        auto mlil = entryFunc->GetMediumLevelIL();
        size_t mlil_idx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), callsite.addr);
        auto instr = mlil->GetInstruction(mlil_idx);
        LogDebug("Checking Callsite at 0x%llx", callsite.addr);
        if(instr.operation == MLIL_CALL || instr.operation == MLIL_TAILCALL)
        {
            auto params = instr.GetParameterExprs();
            if (params.size() == 0)
            {
                // no parameter at call site, check whether it's correctly recognized
                auto constantPtr = instr.GetDestExpr();
                if (constantPtr.operation == MLIL_CONST_PTR)
                {
                    auto addr = constantPtr.GetConstant();
                    auto funcType = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr)->GetType();
                    entryFunc->SetUserCallTypeAdjustment(m_view->GetDefaultArchitecture(), callsite.addr, funcType);
                    m_view->UpdateAnalysisAndWait();
                }
                else
                    LogDebug("Operation not ConstPtr: %d", constantPtr.operation);
            }
            else
                LogDebug("param size not zero");
        }
    }

    string errors;
    QualifiedNameAndType result;
    bool ok;

    string typeString;
    switch (fileType) {
    case PEI: {
        typeString = "EFI_STATUS _ModuleEntry(EFI_PEI_FILE_HANDLE FileHandle, EFI_PEI_SERVICES **PeiServices)";
        ok = m_view->ParseTypeString(typeString, result, errors, {}, true);
        break;
    }

    case DXE: {
        typeString = "EFI_STATUS _ModuleEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)";
        ok = m_view->ParseTypeString(typeString, result, errors, {}, true);
        break;
    }

    case UNKNOWN: {
        LogAlert("Could not identify EFI module type");
        return false;
    }
    }

    if (!ok)
        return false;

    // use UserType so that it would not be overwritten
    entryFunc->SetUserType(result.type);
    m_view->DefineUserSymbol(new Symbol(FunctionSymbol, "_ModuleEntry", entry));
    m_view->UpdateAnalysisAndWait();

    TypePropagation propagater = TypePropagation(m_view);
    return propagater.propagateFuncParamTypes(entryFunc);
}

vector<HighLevelILInstruction> Resolver::HighLevelILExprsAt(Ref<Function> func, Ref<Architecture> arch, uint64_t addr)
{
    auto llil = func->GetLowLevelIL();
    auto mlil = func->GetMediumLevelIL();
    auto hlil = func->GetHighLevelIL();

    size_t llil_idx = func->GetLowLevelILForInstruction(arch, addr);
    size_t llil_expr_idx = llil->GetIndexForInstruction(llil_idx);
    auto mlil_idxes = llil->GetMediumLevelILExprIndexes(llil_expr_idx);

    vector<HighLevelILInstruction> hlils;

    for (size_t mlil_idx : mlil_idxes) {
        auto hlil_idxes = mlil->GetHighLevelILExprIndexes(mlil_idx);
        for (auto hlil_idx : hlil_idxes) {
            auto hlil_expr = hlil->GetExpr(hlil_idx);
            hlils.push_back(hlil_expr);
        }
    }
    return hlils;
}

Ref<Type> Resolver::GetTypeFromViewAndPlatform(string type_name)
{
    QualifiedNameAndType result;
    string errors;
    bool ok = m_view->ParseTypeString(type_name, result, errors);
    if (!ok) {
        // TODO how to retrieve platform types?
    }
    return result.type;
}

bool Resolver::resolveGuidInterface(Ref<Function> func, uint64_t addr, int guid_pos, int interface_pos)
{
    auto hlils = HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr);
    for (auto hlil : hlils) {
        if (hlil.operation != HLIL_CALL)
            continue;

        HighLevelILInstruction instr;
        if (hlil.GetParameterExprs().size() == 1 && hlil.GetParameterExprs()[0].operation == HLIL_CALL)
            instr = hlil.GetParameterExprs()[0];
        else
            instr = hlil;

        auto params = instr.GetParameterExprs();
        if (params.size() <= max(guid_pos, interface_pos))
            continue;

        auto guid_addr = params[guid_pos].GetValue();
        EFI_GUID guid;
        if (guid_addr.state == ConstantValue || guid_addr.state == ConstantPointerValue) {
            if (m_view->Read(&guid, guid_addr.value, 16) < 16)
                continue;
        } else if (guid_addr.state == StackFrameOffset) {
            auto mlil = instr.GetMediumLevelIL();
            int offset = 0;
            vector<uint8_t> contentBytes;
            while (offset < 16) {
                auto var = mlil.GetVariableForStackLocation(guid_addr.value + offset);
                if (!func->GetVariableType(var))
                    break;

                auto width = func->GetVariableType(var)->GetWidth();
                if (width == 0 || width > 8)
                    break;

                auto value = mlil.GetStackContents(guid_addr.value + offset, width);
                int64_t content;
                if (value.state == ConstantValue || value.state == ConstantPointerValue)
                    content = value.value;
                else
                    break;

                for (auto i = 0; i < width; i++) {
                    contentBytes.push_back(static_cast<uint8_t>(content >> (i * 8)));
                }
            }
            if (contentBytes.size() != 16)
                continue;

            memcpy(guid.data(), contentBytes.data(), 16);
        } else if (params[guid_pos].operation == HLIL_VAR) {
            // want to check whether is a protocol wrapper
            auto ssa = params[guid_pos].GetSSAForm();
            HighLevelILInstruction ssa_expr;
            if (ssa.operation != HLIL_VAR_SSA)
                continue;
            if (ssa.GetSSAVariable().version != 0) {
                auto incomming_def = func->GetHighLevelIL()->GetSSAVarDefinition(ssa.GetSSAVariable());
                if (!incomming_def)
                    continue;
                auto incomming_def_ssa = func->GetHighLevelIL()->GetSSAForm()->GetExpr(incomming_def);
                if (incomming_def_ssa.operation != HLIL_VAR_INIT_SSA)
                    continue;
                if (incomming_def_ssa.GetSourceExpr().operation != HLIL_VAR_SSA)
                    continue;
                if (incomming_def_ssa.GetSourceExpr().GetSSAVariable().version != 0)
                    continue;
                ssa_expr = incomming_def_ssa.GetSourceExpr();
            } else
                ssa_expr = ssa;

            auto func_params = func->GetParameterVariables().GetValue();
            bool found = false;
            int incoming_guid_idx;
            for (int i = 0; i < func_params.size(); i++) {
                if (func_params[i] == ssa_expr.GetSSAVariable().var) {
                    incoming_guid_idx = i;
                    found = true;
                    break;
                }
            }
            if (!found)
                continue;

            // see if output interface varible is an incoming parameter
            auto interface_instr_ssa = params[interface_pos].GetSSAForm();
            if (interface_instr_ssa.operation != HLIL_VAR_SSA)
                continue;

            if (interface_instr_ssa.GetSSAVariable().version != 0) {
                auto incoming_def = func->GetHighLevelIL()->GetSSAForm()->GetSSAVarDefinition(interface_instr_ssa.GetSSAVariable());
                auto def_expr = func->GetHighLevelIL()->GetSSAForm()->GetExpr(incoming_def);
                if (def_expr.operation != HLIL_VAR_INIT_SSA)
                    continue;
                if (def_expr.GetSourceExpr().operation != HLIL_VAR_SSA)
                    continue;
                if (def_expr.GetSourceExpr().GetSSAVariable().version != 0)
                    continue;
                interface_instr_ssa = def_expr.GetSourceExpr();
            }
            found = false;
            int incoming_interface_idx;
            for (int i = 0; i < func_params.size(); i++) {
                if (func_params[i] == interface_instr_ssa.GetSSAVariable().var) {
                    incoming_interface_idx = i;
                    found = true;
                    break;
                }
            }
            if (!found)
                continue;

            LogInfo("Found EFI Protocol wrapper at 0x%llx, checking reference to this function", addr);

            auto refs = m_view->GetCodeReferences(func->GetStart());
            for (auto ref : refs)
                resolveGuidInterface(ref.func, ref.addr, incoming_guid_idx, incoming_interface_idx);
            continue;
        }

        if (guid.empty())
            continue;
        auto names = lookupGuid(guid);
        string protocol_name = names.first;
        string guid_name = names.second;

        if (protocol_name.empty()) {
            // protocol name is empty
            if (!guid_name.empty()) {
                // user added guid, check whether the user has added the protocol type
                string possible_protocol_type = guid_name;
                size_t pos = possible_protocol_type.rfind("_GUID");
                if (pos != string::npos)
                    possible_protocol_type.erase(pos, 5);

                // check whether `possible_protocol_type` is in bv.types
                QualifiedNameAndType result;
                string errors;
                bool ok = m_view->ParseTypeString(possible_protocol_type, result, errors);
                if (ok)
                    protocol_name = possible_protocol_type;
            } else {
                // use UnknownProtocol as defult
                LogWarn("Unknown EFI Protocol referenced at 0x%llx", addr);
                guid_name = nonConflictingName("UnknownProtocolGuid");
            }
        }

        // now we just need to rename the GUID and apply the protocol type
        auto sym = m_view->GetSymbolByAddress(guid_addr.value);
        auto guid_var_name = guid_name;
        if (sym)
            guid_var_name = sym->GetRawName();

        QualifiedNameAndType result;
        string errors;
        bool ok = m_view->ParseTypeString("EFI_GUID", result, errors);
        if (!ok)
            return false;
        m_view->DefineDataVariable(guid_addr.value, result.type);
        m_view->DefineUserSymbol(new Symbol(DataSymbol, guid_var_name.c_str(), guid_addr.value));

        if (protocol_name.empty()) {
            LogWarn("Found unknown protocol at 0x%llx", addr);
            protocol_name = "VOID*";
        }

        auto protocol_type = GetTypeFromViewAndPlatform(protocol_name);
        if (!protocol_type)
            continue;
        protocol_type = Type::PointerType(m_view->GetDefaultArchitecture(), protocol_type);
        auto interface_param = params[interface_pos];
        if (interface_param.operation == HLIL_ADDRESS_OF) {
            interface_param = interface_param.GetSourceExpr();
            if (interface_param.operation == HLIL_VAR) {
                string interface_name = guid_name;
                if (guid_name.substr(0, 19) == "UnknownProtocolGuid") {
                    interface_name.replace(0, 19, "UnknownProtocolInterface");
                    interface_name = nonConflictingLocalName(func, interface_name);
                } else {
                    interface_name = nonConflictingLocalName(func, GetVarNameForTypeStr(guid_name));
                }
                func->CreateUserVariable(interface_param.GetVariable(),
                    protocol_type,
                    interface_name);
            }
        } else if (interface_param.operation == HLIL_CONST_PTR) {
            auto dataVarAddr = interface_param.GetValue().value;
            m_view->DefineDataVariable(dataVarAddr, protocol_type);
            string interfaceName = guid_name;
            if (interfaceName.find("GUID") != interfaceName.npos) {
                interfaceName.replace(interfaceName.find("GUID"), 4, "INTERFACE");
                interfaceName = GetVarNameForTypeStr(interfaceName);
            } else if (guid_name.substr(0, 19) == "UnknownProtocolGuid") {
                interfaceName.replace(15, 4, "Interface");
            }
            m_view->DefineUserSymbol(new Symbol(DataSymbol, interfaceName, dataVarAddr));
        }
        m_view->UpdateAnalysisAndWait();
    }

    return true;
}

bool Resolver::defineTypeAtCallsite(Ref<Function> func, uint64_t addr, const string typeName, int paramIdx, bool followFields)
{
    auto mlil = func->GetMediumLevelIL();
    size_t mlil_idx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), addr);
    auto instr = mlil->GetInstruction(mlil_idx);

    auto params = instr.GetParameterExprs();
    if (params.size() < paramIdx + 1)
        return false;

    auto param = params[paramIdx];
    if (param.operation != MLIL_CONST_PTR)
        return false;

    // TODO need to filter those pointed to strang locations (null pointer for example)
    // probably we want to make sure this pointer points to data section (but it's also
    // very common that UEFI binaries may not have data sections)

    uint64_t varAddr = param.GetConstant();
    DataVariable datavar;
    auto ok = m_view->GetDataVariableAtAddress(varAddr, datavar);
    if (ok) {
        string datavarTypeName = datavar.type.GetValue()->GetTypeName().GetString();
        if (datavarTypeName.find(typeName) != datavarTypeName.npos)
            // the variable already has this type, return
            return false;
    }

    // Now we want to define the type at varAddr

    if (typeName == "EFI_GUID") {
        // If it's GUID, we want to define it with name
        defineAndLookupGuid(varAddr);
        // defining a GUID should never fail. Also it can not have fields
        return true;
    }

    QualifiedNameAndType result;
    string errors;
    ok = m_view->ParseTypeString(typeName, result, errors);
    if (!ok) {
        LogError("Cannot parse type %s when trying to define type at 0x%llx", typeName.c_str(), addr);
        return false;
    }

    m_view->DefineDataVariable(varAddr, result.type);

    if (!followFields)
        return true;

    // We want to define the Guid field and the Notify field, which are both pointers
    DataVariable structVar;
    ok = m_view->GetDataVariableAtAddress(varAddr, structVar);
    if (!ok)
        return false;

    if (!structVar.type.GetValue()->IsNamedTypeRefer())
        return false;

    auto structTypeId = structVar.type.GetValue()->GetNamedTypeReference()->GetTypeId();
    auto structStructureType = m_view->GetTypeById(structTypeId)->GetStructure();

    if (!structStructureType)
        return false;
    auto members = structStructureType->GetMembers();

    // we want to keep this name for renaming NotifyFunction
    string guidName;
    for (auto member : members) {
        auto memberOffset = member.offset;
        auto memberType = member.type.GetValue();
        auto memberName = member.name;

        // we only want to define pointers
        if (!memberType->IsPointer() && !(memberType->IsNamedTypeRefer() && memberName == "Notify"))
            continue;

        if (memberName == "Guid") {
            uint64_t guidAddr = 0;
            m_view->Read(&guidAddr, varAddr + memberOffset, m_view->GetAddressSize());
            auto name = defineAndLookupGuid(guidAddr);
            guidName = name.second;
        } else if (memberName == "Notify") {
            // Notify has the type EFI_NOTIFY_ENTRY_POINT
            // which is a NamedTypeRefer
            uint64_t funcAddr;
            m_view->Read(&funcAddr, varAddr + memberOffset, m_view->GetAddressSize());
            auto notifyFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), funcAddr);
            if (!notifyFunc)
                continue;

            string funcName = guidName;
            if (guidName.empty())
                funcName = nonConflictingName("UnknownNotify");
            else
                funcName = "Notify" + funcName.replace(funcName.find("GUID"), 4, "");

            string notifyTypeStr = "EFI_STATUS Notify(EFI_PEI_SERVICES **PeiServices, EFI_PEI_NOTIFY_DESCRIPTOR* NotifyDescriptor, VOID* Ppi)";
            ok = m_view->ParseTypeString(notifyTypeStr, result, errors);
            notifyFunc->SetUserType(result.type);
            m_view->DefineUserSymbol(new Symbol(FunctionSymbol, funcName, funcAddr));
            m_view->UpdateAnalysisAndWait();

            TypePropagation propagator(m_view);
            propagator.propagateFuncParamTypes(notifyFunc);
        }
    }
    return true;
}

Resolver::Resolver(Ref<BinaryView> view, Ref<BackgroundTask> task)
{
    m_view = view;
    m_task = task;
    m_width = m_view->GetAddressSize();
}

pair<string, string> Resolver::lookupGuid(EFI_GUID guidBytes)
{
    auto it = m_protocol.find(guidBytes);
    if (it != m_protocol.end())
        return it->second;

    auto user_it = m_user_guids.find(guidBytes);
    if (user_it != m_user_guids.end())
        return make_pair(string(), user_it->second);

    return pair<string, string>();
}

pair<string, string> Resolver::defineAndLookupGuid(uint64_t addr)
{
    EFI_GUID guidBytes;
    try {
        auto readSize = m_view->Read(&guidBytes, addr, 16);
        if (readSize != 16)
            return make_pair(string(), string());
    } catch (ReadException) {
        LogError("Read GUID failed at 0x%llx", addr);
        return make_pair(string(), string());
    }
    auto namePair = lookupGuid(guidBytes);
    string protocolName = namePair.first;
    string guidName = namePair.second;

    QualifiedNameAndType result;
    string errors;
    // must use ParseTypeString,
    // m_view->GetTypeByName() doesn't return a NamedTypeReference and the DataRenderer doesn't applied
    bool ok = m_view->ParseTypeString("EFI_GUID", result, errors);
    if (!ok)
        return make_pair(string(""), string(""));
    m_view->DefineDataVariable(addr, result.type);
    if (guidName.empty()) {
        m_view->DefineUserSymbol(new Symbol(DataSymbol, nonConflictingName("UnknownGuid").c_str(), addr));
        LogDebug("Found UnknownGuid at 0x%llx", addr);
    } else {
        m_view->DefineUserSymbol(new Symbol(DataSymbol, guidName.c_str(), addr));
        LogDebug("Define %s at 0x%llx", guidName.c_str(), addr);
    }

    return namePair;
}
