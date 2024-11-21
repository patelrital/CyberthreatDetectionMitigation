import pefile

# List of API signatures commonly used by malware
malware_api_signatures = [api + 'malware' for api in [
    "openprocess",
    "virtualallocex", 
    "writeprocessmemory",
    "loadlibrarya",
    "loadresource",
    "getprocaddress", 
    "createremotethread",
    "writefile",
    "istrcmpia",
    "readfile",
    "deletefilea",
    "copyfilea",
    "createprocessa",
    "findfirstfilea", 
    "createprocess",
    "getwindowsdirectory",
    "regsetvalueexa",
    "regenumvaluea", 
    "regdeletekeya",
    "regcreatekeyexa",
    "openprocesstoken",
    "cryptcreatehash",
    "crypthashdata",
    "cryptgethashparam",
    "cryptacquirecontexta",
    "writefile",
    "readfile",
    "createfile",
    "copyfile",
    "movefile", 
    "ntquerydirectoryfile",
    "createfilea",
    "createfilew",
    "loadlibrary",
    "createthread",
    "resumethread",
    "createremotethread",
    "mouse_event",
    "keybd_event",
    "getasynckeystate",
    "attachthreadinput",
    "internetwritefile",
    "internetconnect",
    "internetopenurl", 
    "internetreadfile",
    "wsastartup",
    "gethostbyname",
    "gethostbyaddr",
    "socket",
    "send_recv",
    "inet_addr",
    "bind",
    "connect",
    "accept",
    "connectnamepipe",
    "urldownloadtofile",
    "netshareenum",
    "ftpopenfile",
    "ftpgetfilesize",
    "shellexecute",
    "sfcterminatewatcherthread",
    "samqueryinformationuse",
    "openmutex",
    "outputdebugstring",
    "isntadmin",
    "iswow64process",
    "virtualallocex",
    "virtualprotectex",
    "writeprocessmemory"
]]

# Common text patterns to detect in hex analysis
suspicious_text_patterns = [
    b'windows', b'Windows', b'telnet', b'Telnet', b'ssh', b'Ssh', b'SSH', 
    b'ftp', b'ftp', b'ftp-server', b'FTP-Server', b'rdp', b'rdp.exe', b'RDP',
    b'C:\\', b'C:\\Windows', b'hosts.exe', b'Hosts.exe', b'regedit', b'Regedit.exe',
    b'Registry', b'registry', b'appdata', b'AppData', b'APPDATA', b'%AppData%',
    b'%appdata%', b'Program', b'Programs', b'Program Files', b'Program Files (x86)',
    b'C:\\Users', b'Users', b'User', b'users', b'C:\\Users\\Administrator',
    b'administrator', b'Administrator', b'admin'
]

def extract_pe_features(pe_file: pefile.PE) -> (list, list, list):
    """
    Extract DLL imports, API calls and section names from a PE file
    
    Args:
        pe_file: A pefile.PE instance
        
    Returns:
        Tuple containing lists of (dll_names, api_calls, section_names)
    """
    dll_names = []
    api_calls = []
    section_names = []

    try:
        for entry in pe_file.DIRECTORY_ENTRY_IMPORT:
            dll_names.append(entry.dll.decode("utf8"))
            
            for imp in entry.imports:
                if imp.name:
                    api_calls.append(imp.name.decode('utf8'))
    except:
        print('No DIRECTORY_ENTRY_IMPORT found!')

    for section in pe_file.sections:
        name = str(section.Name.decode("utf8")).strip('\x00')
        section_names.append(name)

    return dll_names, api_calls, section_names

def extract_pe_header_features(pe_file: pefile.PE) -> list:
    """
    Extract numerical features from PE headers
    
    Args:
        pe_file: A pefile.PE instance
        
    Returns:
        List of numerical header features
    """
    virtual_addresses = [d.VirtualAddress for d in pe_file.OPTIONAL_HEADER.DATA_DIRECTORY]
    sizes = [d.Size for d in pe_file.OPTIONAL_HEADER.DATA_DIRECTORY]

    # Pad to expected length of 16
    if len(virtual_addresses) == 15:
        virtual_addresses.append(0)
    if len(sizes) == 15:
        sizes.append(0)

    header_features = [
        virtual_addresses, sizes,
        pe_file.DOS_HEADER.e_magic, pe_file.DOS_HEADER.e_cblp, pe_file.DOS_HEADER.e_cp,
        pe_file.DOS_HEADER.e_crlc, pe_file.DOS_HEADER.e_cparhdr, pe_file.DOS_HEADER.e_minalloc,
        pe_file.DOS_HEADER.e_maxalloc, pe_file.DOS_HEADER.e_ss, pe_file.DOS_HEADER.e_sp,
        pe_file.DOS_HEADER.e_csum, pe_file.DOS_HEADER.e_ip, pe_file.DOS_HEADER.e_cs,
        pe_file.DOS_HEADER.e_lfarlc, pe_file.DOS_HEADER.e_oemid, pe_file.DOS_HEADER.e_oeminfo,
        pe_file.DOS_HEADER.e_lfanew,

        pe_file.FILE_HEADER.Machine, pe_file.FILE_HEADER.NumberOfSections,
        pe_file.FILE_HEADER.PointerToSymbolTable, pe_file.FILE_HEADER.NumberOfSymbols,
        pe_file.FILE_HEADER.SizeOfOptionalHeader, pe_file.FILE_HEADER.Characteristics,

        pe_file.OPTIONAL_HEADER.Magic, pe_file.OPTIONAL_HEADER.MajorLinkerVersion,
        pe_file.OPTIONAL_HEADER.MinorLinkerVersion, pe_file.OPTIONAL_HEADER.SizeOfCode,
        pe_file.OPTIONAL_HEADER.SizeOfInitializedData, pe_file.OPTIONAL_HEADER.SizeOfUninitializedData,
        pe_file.OPTIONAL_HEADER.AddressOfEntryPoint, pe_file.OPTIONAL_HEADER.BaseOfCode,
        pe_file.OPTIONAL_HEADER.ImageBase, pe_file.OPTIONAL_HEADER.SectionAlignment,
        pe_file.OPTIONAL_HEADER.FileAlignment, pe_file.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        pe_file.OPTIONAL_HEADER.MinorOperatingSystemVersion, pe_file.OPTIONAL_HEADER.MajorImageVersion,
        pe_file.OPTIONAL_HEADER.MinorImageVersion, pe_file.OPTIONAL_HEADER.MajorSubsystemVersion,
        pe_file.OPTIONAL_HEADER.MinorSubsystemVersion, pe_file.OPTIONAL_HEADER.Reserved1,
        pe_file.OPTIONAL_HEADER.SizeOfImage, pe_file.OPTIONAL_HEADER.SizeOfHeaders,
        pe_file.OPTIONAL_HEADER.CheckSum, pe_file.OPTIONAL_HEADER.Subsystem,
        pe_file.OPTIONAL_HEADER.DllCharacteristics, pe_file.OPTIONAL_HEADER.SizeOfStackReserve,
        pe_file.OPTIONAL_HEADER.SizeOfStackCommit, pe_file.OPTIONAL_HEADER.SizeOfHeapReserve,
        pe_file.OPTIONAL_HEADER.SizeOfHeapCommit, pe_file.OPTIONAL_HEADER.LoaderFlags,
        pe_file.OPTIONAL_HEADER.NumberOfRvaAndSizes
    ]

    # Flatten nested lists into single list
    flattened = []
    [flattened.extend(x) if isinstance(x, list) else flattened.append(x) for x in header_features]

    return flattened