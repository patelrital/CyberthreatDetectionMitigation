import threading
import pefile
import PE_IMAGE_SIGNATRUEs
import numpy as np
import pickle
from Parsing_CSV import Open_Csv # CSV editor
from virus_total_api import VirusTotal_class
from Vt_analyse_data_to_DeepLearning_data import Vt_analysed_List__To__DeepLearning_list # Convert VT results to dataset

def make_one_hot_encoding(original_labels: list) -> tuple:
    """
    Create one-hot encoded labels from original labels
    Returns:
        Tuple containing:
        - List of unique label names 
        - One-hot encoded labels
    """
    unique_labels = []
    # Extract unique labels
    for label in original_labels:
        if label not in unique_labels:
            unique_labels.append(label)
            
    # Create one-hot encoding
    one_hot_encoded = []
    for label in original_labels:
        encoding = [0] * len(unique_labels)
        encoding[unique_labels.index(label)] = 1
        one_hot_encoded.append(encoding)
        
    return unique_labels, one_hot_encoded

def Get_X_from_EXE_bin(
    EXE_bin: bytes = None,
    loaded_x_for_dll_api_section_Malware: list = None,
    Client_VT_instance: VirusTotal_class = None, 
    SHA256: str = None,  # SHA256 of target EXE
    SERVER_VT_CSV_MANAGER: Open_Csv = None
) -> tuple:  # Returns (features, vt_success)

    if (len(EXE_bin) < 4) or (EXE_bin == None):
        return None, None

    try:
        pe_image = pefile.PE(data=EXE_bin)
    except:
        print("Failed to parse PE")
        return None, None

    # Initialize feature vector
    features = [0] * len(loaded_x_for_dll_api_section_Malware)

    # Extract DLLs, APIs and sections
    dlls, apis, sections = PE_IMAGE_SIGNATRUEs.Getting_Dll_API_SECTION(pe_image)
    collected = dlls + apis + sections
    
    # Set features for matching signatures
    for item in collected:
        # Regular signature match
        if item in loaded_x_for_dll_api_section_Malware:
            features[loaded_x_for_dll_api_section_Malware.index(item)] = 1

        # Malware signature match 
        malware_sig = str(item) + "malware"
        if malware_sig in loaded_x_for_dll_api_section_Malware:
            features[loaded_x_for_dll_api_section_Malware.index(malware_sig)] = 1

    # Add PE header features
    features += PE_IMAGE_SIGNATRUEs.Getting_PE_HEADER(pe_image)

    # Check for malware strings in binary
    malware_string_features = [0] * len(PE_IMAGE_SIGNATRUEs.signature_text)
    for i, sig in enumerate(PE_IMAGE_SIGNATRUEs.signature_text):
        if sig in EXE_bin:
            malware_string_features[i] = 1
    features += malware_string_features

    # Process VirusTotal results
    vt_success = False
    vt_row = SERVER_VT_CSV_MANAGER.Output_one_row(SHA256, 0)
    
    if vt_row is None:
        print("No existing VT analysis found")
        try:
            # Run VT scan
            _, result_list, _ = Client_VT_instance.Start_Scan(
                Binary_DATA=EXE_bin,
                Path=None, 
                Binary_DATA_SHA256=SHA256
            )

            # Convert results to features
            vt_features = Vt_analysed_List__To__DeepLearning_list(
                input_vt_list=result_list
            )

            # Save to CSV
            SERVER_VT_CSV_MANAGER.APPEND_row([SHA256] + vt_features)
            vt_success = True
            
        except:
            print("VT API error - padding with zeros")
            vt_features = [0] * 937
            vt_success = False
    else:
        print("Found existing VT analysis")
        vt_features = vt_row[1:]  # Exclude SHA256
        vt_success = True

    features += vt_features

    print(f"Final feature vector length: {len(features)}")
    return np.asarray([features], dtype=object), vt_success

def MAKING_x_y_for_TRAINNING(
    EXE_PATH_LIST_from_Main_csv: list = None,  # List of (path, sha256, label) tuples
    SAVE_INDEX: str = None,
    SAVE_LOCK: threading.Lock = None,
    Server_VT_instance: VirusTotal_class = None,
    SERVER_VT_CSV_MANAGER: Open_Csv = None
):
    """
    Create training features and labels from PE files
    """
    # Load valid PE files
    valid_pe_files = []  # List of (pe_obj, path, sha256, label)
    for path, sha256, label in EXE_PATH_LIST_from_Main_csv:
        try:
            with open(path, 'rb') as f:
                exe_data = f.read()
            valid_pe_files.append([
                pefile.PE(data=exe_data), 
                path,
                sha256,
                label
            ])
        except:
            print(f"Failed to load PE file: {path}")
            continue

    # Extract unique DLLs, APIs and sections
    all_dlls = []
    all_apis = [] 
    all_sections = []
    
    for pe_obj, _, _, _ in valid_pe_files:
        dlls, apis, sections = PE_IMAGE_SIGNATRUEs.Getting_Dll_API_SECTION(pe_obj)
        
        for dll in dlls:
            if dll not in all_dlls:
                all_dlls.append(dll)
                
        for api in apis:
            if api not in all_apis:
                all_apis.append(api)
                
        for section in sections:
            if section not in all_sections:
                all_sections.append(section)

    # Create feature columns
    feature_columns = all_dlls + all_apis + all_sections + PE_IMAGE_SIGNATRUEs.pe_malware_api_signature

    # Generate feature vectors
    X = []
    for pe_obj, path, sha256, _ in valid_pe_files:
        features = [0] * len(feature_columns)

        # Basic PE features
        dlls, apis, sections = PE_IMAGE_SIGNATRUEs.Getting_Dll_API_SECTION(pe_obj)
        for item in dlls + apis + sections:
            if item in feature_columns:
                features[feature_columns.index(item)] = 1
            
            malware_sig = f"{item}malware"
            if malware_sig in feature_columns:
                features[feature_columns.index(malware_sig)] = 1

        # Add PE header features
        features += PE_IMAGE_SIGNATRUEs.Getting_PE_HEADER(pe_obj)

        # Check malware strings
        with open(path, 'rb') as f:
            exe_data = f.read()
            string_features = [0] * len(PE_IMAGE_SIGNATRUEs.signature_text)
            for i, sig in enumerate(PE_IMAGE_SIGNATRUEs.signature_text):
                if sig in exe_data:
                    string_features[i] = 1
        features += string_features

        # Add VT features
        vt_row = SERVER_VT_CSV_MANAGER.Output_one_row(sha256, 0)
        if vt_row is None:
            try:
                _, vt_results, _ = Server_VT_instance.Start_Scan(
                    Binary_DATA=None,
                    Path=path,
                    Binary_DATA_SHA256=sha256
                )
                vt_features = Vt_analysed_List__To__DeepLearning_list(vt_results)
                SERVER_VT_CSV_MANAGER.APPEND_row([sha256] + vt_features)
            except:
                print("VT API error - using zero features")
                vt_features = [0] * 937
        else:
            vt_features = vt_row[1:]
            
        features += vt_features
        X.append(features)

    # Convert to numpy arrays
    X = np.asarray(X, dtype=object)
    
    # Create one-hot encoded labels
    label_names, y = make_one_hot_encoding([f[3] for f in valid_pe_files])
    y = np.array(y)

    # Save feature columns and label names
    with SAVE_LOCK:
        with open(f"{SAVE_INDEX}_x", 'wb') as f:
            pickle.dump(feature_columns, f, protocol=5)
        with open(f"{SAVE_INDEX}_y", 'wb') as f:
            pickle.dump(label_names, f, protocol=5)

    return X, y
