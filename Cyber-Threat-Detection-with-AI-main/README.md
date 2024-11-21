# AI-based Malware Detection with VirusTotal and MalwareBazaar

CDC HACKATHON PROJECT

This project implements malware detection using Python 3.9, leveraging the VirusTotal API and pefile module combined with TensorFlow AI. The system analyzes executable files to detect malicious code by extracting key features from PE headers, API calls, DLL imports and section characteristics. These features are combined with VirusTotal analysis results to train a deep neural network for accurate malware classification.

## Features

- Parallel dataset construction for both malware and benign samples
- Automated dataset building using custom CSV module 
- Asynchronous data collection while instance is active
- Support for non-malware directory scanning
- Integration with MalwareBazaar API for initial malware samples
- Thread-safe asynchronous collection with mutex locks
- Dataset stored in SHARE_ai_exe_dataset.csv by default

## X Data Structure for AI Training

The X data structure consists of features extracted from PE files including DLL imports, API calls, section characteristics and PE header information.

## Quick Start Guide

1. Download the latest release zip file
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Add your VirusTotal API keys in NEW_AI_instance.py
4. Run the main script:
   ```
   python MAIN/NEW_AI_instance.py
   ```
5. The system will automatically:
   - Build initial dataset
   - Train the model
   - Begin accepting files for prediction

## Additional Information

The code implements mutex locks using threading.Lock() for thread safety in multi-threaded environments, intended for cloud AI analysis server services. Thread safety is not required for single-user scenarios.

Note that different VirusTotal API keys are required for instance creation versus prediction. The prediction API key is needed to generate X data features (if not provided, those features will be set to 0).

## Advantages

1. Reduces VirusTotal API usage by caching analysis results in VT_analysed.csv

2. Improves training speed by normalizing X data using scikit-learn's MinMaxScaler() to scale values between 0.0 and 1.0

## Current Limitations

1. The automated model generation may add Dropout layers suboptimally. The model architecture automation needs improvement.

2. Prediction results are incorporated into the training dataset (updating existing rows with matching SHA256). While this enables automated dataset growth, it could be detrimental if initial prediction accuracy is low due to insufficient training data.

## Code Structure

### 1. NEW_AI_instance.py
- Entry point module
- Creates instance and manages training/prediction workflow
- Handles model persistence

### 2. PE_IMAGE_SIGNATURES.py  
- Extracts signature features from EXE files using pefile
- Provides DLL/API/Section extraction
- Extracts PE header features

### 3. Make_X_only_EXE.py
- Generates X data features for prediction
- Creates X,y data pairs for training
- Handles one-hot encoding of labels

### 4. Model_Configure.py
- Automatically generates TensorFlow model architecture
- Uses Functional API to construct layers
- Scales architecture based on input dimensions

### 5. virus_total_api.py
- Wrapper class for VirusTotal API integration
- Handles file scanning and result parsing
- Manages API request flow and rate limiting

### 6. Vt_analyse_data_to_DeepLearning_data.py
- Converts VirusTotal analysis results to numeric features
- Ensures consistent feature vector length
- Handles encoding of categorical data

### 7. Parsing_CSV.py
- Utility module for CSV operations
- Provides methods for reading, appending and updating
- Handles data persistence and management
