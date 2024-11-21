# Main Directory

This directory contains the core modules and components of the AI-based malware detection system. The key modules include:

## Core Modules

### NEW_AI_instance.py
- Main entry point for creating and managing AI instances
- Handles training, prediction and lifecycle management
- Controls dataset collection threads

### PE_IMAGE_SIGNATURES.py
- Extracts features from PE/EXE files using pefile
- Analyzes DLL imports, API calls and section characteristics
- Generates signature-based features for detection

### Make_X_only_EXE.py 
- Generates feature vectors for prediction
- Creates training data pairs
- Handles feature encoding and normalization

### Model_Configure.py
- Configures and generates TensorFlow model architecture
- Uses Functional API for flexible model construction
- Automatically scales based on input dimensions

### virus_total_api.py
- Integrates with VirusTotal API
- Handles file scanning and result parsing
- Manages API request flow and rate limiting

### Vt_analyse_data_to_DeepLearning_data.py
- Converts VirusTotal results to numeric features
- Ensures consistent feature vector dimensions
- Handles categorical data encoding

### Parsing_CSV.py
- Utility module for CSV operations
- Provides methods for reading/writing data
- Manages dataset persistence

## Key Files

- SHARE_ai_exe_dataset.csv: Main dataset file containing training samples
- VT_analysed.csv: Cache of VirusTotal analysis results

## Usage

1. Create an AI instance using NEW_AI_instance.py
2. Configure training parameters
3. Call Start_Train() to begin training
4. Use Start_Prediction() for malware detection
5. Call Terminate() before exiting

The modules work together to provide a complete malware detection pipeline using machine learning and signature analysis.
