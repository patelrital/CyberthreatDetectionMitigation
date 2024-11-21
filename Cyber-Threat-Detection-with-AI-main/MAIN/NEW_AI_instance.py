import hashlib
import struct
import pandas as pd
import tensorflow as tf
import numpy as np
import pickle
import threading
import os
import io
import pyzipper

from virus_total_api import VirusTotal_class
from Parsing_CSV import Open_Csv # CSV editor
from Make_X_only_EXE import Get_X_from_EXE_bin, MAKING_x_y_for_TRAINNING
from crypto_utils import CryptoManager

class AI_Instance():
    def __init__(self, server_vt_api:str=None, vt_csv_path:str=None, main_csv_path:str=None, save_index:str=None,
                 benign_exes_dir:str=".\\Normal_EXE\\", # [v2.1] 
                 run_benign_parallel:bool=True # [v2.1]
                ):
        # Server VT API only used for training. Rest is client responsibility

        self.lock_main_csv = threading.Lock() # Lock for main CSV access
        self.lock_vt_csv = threading.Lock() # Lock for VT results CSV access  
        self.lock_model = threading.Lock() # Lock for model save/load
        self.lock_extra = threading.Lock() # Lock for x,y save/load

        if not all([server_vt_api, main_csv_path, save_index, vt_csv_path]):
            print("Some constructor parameters are missing")
            return

        self.server_vt_api = server_vt_api
        self.vt_csv_path = vt_csv_path  
        self.main_csv_path = main_csv_path
        self.save_index = save_index

        self.vt_instance = VirusTotal_class(
            API_KEY=self.server_vt_api
        )

        self.main_csv_manager = Open_Csv( # Main CSV read/write instance
            Input_Csv_Path=self.main_csv_path
        )

        self.vt_csv_manager = Open_Csv( # VT CSV read/write instance
            Input_Csv_Path=self.vt_csv_path
        )

        '''
        Create datasets [NEW]
        Must save to MAIN_CSV
        '''

        # Malware collection
        self.malware_thread:threading.Thread = None # [v2.0]
        self.malware_thread_terminate = False # [v2.1]
        print("[Starting parallel thread] -> self.malware_thread") # [v2.0]
        self.malware_thread = threading.Thread(
            target=self.collect_malware_parallel,
            args=("950d8ef3adefd3bc05a1ed8174877949",)
        ) # [v2.0]
        self.malware_thread.start() # [v2.0]

        # Benign EXE collection from PortableApps
        self.benign_thread:threading.Thread = None # [v2.1]
        self.benign_thread_terminate = False # [v2.1]
        if benign_exes_dir:
            print("[Starting parallel thread] -> self.benign_thread")
            self.benign_thread = threading.Thread(
                target=self.collect_benign_parallel,
                args=(benign_exes_dir,)
            ) # [v2.1]
            self.benign_thread.start() # [v2.1]

    def collect_benign_parallel(self, directory:str=None): # [v2.1]
        print("Starting benign data collection")
        
        while True:
            if self.benign_thread_terminate:
                return

            # Collect all EXEs from PortableApps directory
            benign_exe_paths = []
            for root, dirs, files in os.walk(f"{directory}"):
                if len(files) < 1:
                    print("No benign EXEs found")
                    break
                    
                for file_name in files:
                    benign_exe_paths.append(f"{directory}{file_name}")

            for exe_path in benign_exe_paths:
                # Calculate SHA256 hash
                with open(exe_path, 'rb') as f:
                    file_bytes = f.read()
                sha256 = hashlib.sha256(file_bytes).hexdigest()

                with self.lock_main_csv:
                    # Check for duplicates before adding to CSV
                    existing = self.main_csv_manager.Output_one_row(
                        specified_hint=sha256,
                        index_hint=1
                    )

                    if not existing:
                        print("No existing entry found")
                        self.main_csv_manager.Write_to_Csv(
                            Input_data=[exe_path, sha256, "benign"]
                        )

    def collect_malware_parallel(self, api:str=None): # [v2.0]
        from Malware_Bazaar import Malware_Bazaar_Manager

        malware_manager = Malware_Bazaar_Manager(API=api)
        target_count = 10
        current_count = 0

        while True:
            if self.malware_thread_terminate:
                return # [v2.1]

            if target_count > 1000:
                print("Maximum samples reached!")
                target_count = 1000

            malware_samples = malware_manager.Make_sample_to_DISK_for_malware_DATASET(
                file_type="exe",
                get_count=target_count,
                save_path=".\\Malware_EXE\\"
            )

            if not malware_samples:
                target_count += 20
                current_count += 20
                continue

            for sample_path in malware_samples:
                with self.lock_main_csv:
                    # Check for duplicates
                    existing = self.main_csv_manager.Output_one_row(
                        specified_hint=str(sample_path),
                        index_hint=0
                    )
                    
                    if not existing:
                        # Extract SHA256 from filename
                        sha256 = str(sample_path).split("\\")[-1].split(".")[0].split("_from_malware")[0]
                        self.main_csv_manager.Write_to_Csv(
                            Input_data=[sample_path, sha256, "malware"]
                        )

            target_count += 20
            current_count = len(malware_samples)

            if target_count >= current_count:
                print("Incomplete sample set, retrying")
                target_count += 1
                current_count += 1

    def Start_Train(self,
                   epoch:int=100, 
                   batch_size:int=2,
                   validation_split:float=0.2,
                   learning_rate:float=0.001,
                   patience:int=25,
                   min_delta:float=0.1):

        exe_paths = []
        sha256_hashes = []
        labels = []

        with self.lock_main_csv:
            df = pd.read_csv(self.main_csv_path)
            exe_paths = [str(i) for i in df['values']]
            sha256_hashes = [str(i) for i in df['sha256']]
            labels = [str(i) for i in df['types']]

        X = None
        y = None
        with self.lock_vt_csv:
            # Generate features and labels
            X, y = MAKING_x_y_for_TRAINNING(
                EXE_PATH_LIST_from_Main_csv=zip(exe_paths, sha256_hashes, labels),
                SAVE_INDEX=self.save_index,
                SAVE_LOCK=self.lock_extra,
                SERVER_VT_CSV_MANAGER=self.vt_csv_manager,
                Server_VT_instance=self.vt_instance
            )

        # Preprocess features
        scaler = MinMaxScaler()
        X_scaled = scaler.fit_transform(X)

        # Split training data
        x_train, x_valid, y_train, y_valid = train_test_split(X_scaled, y, test_size=0.2)

        # Build model
        from Model_Configure import Make_Model_Layers
        model = Make_Model_Layers(
            X=X,
            y=y, 
            ALL_of_LAYERS_count=6
        )

        # Compile model
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )

        # Add early stopping
        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=patience,
            min_delta=min_delta,
            restore_best_weights=True
        )

        # Train model
        model.fit(
            x_train, y_train,
            epochs=epoch,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=[early_stopping]
        )

        # Save model and scaler
        with self.lock_model:
            try:
                tf.keras.models.save_model(
                    model=model,
                    filepath=f'{self.save_index}_model'
                )
            except:
                try:
                    model.export(f'{self.save_index}_model')
                except:
                    model.save(f'{self.save_index}_model')

            try:
                with open(f"{self.save_index}_scaler", 'wb') as f:
                    pickle.dump(scaler, f, protocol=5)
            except:
                print("Failed to save scaler")

    def Start_Prediction(self, client_vt_api:str=None, exe_bytes:bytes=None):
        if not client_vt_api:
            print("Client VT API required")
            return

        # Load model and data
        model = None
        feature_data = None
        label_data = None
        scaler = None

        with self.lock_model:
            try:
                model = tf.keras.models.load_model(f'{self.save_index}_model')
            except:
                print("Failed to load model")
                return

            try:
                with open(f"{self.save_index}_x", 'rb') as fx:
                    with open(f"{self.save_index}_y", 'rb') as fy:
                        feature_data = pickle.load(fx)
                        label_data = pickle.load(fy)
            except:
                print("Failed to load feature/label data")
                return

            try:
                with open(f"{self.save_index}_scaler", 'rb') as f:
                    scaler = pickle.load(f)
            except:
                print("Failed to load scaler")
                return

        print(model, feature_data, label_data, scaler)

        # Create client VT instance
        client_vt = VirusTotal_class(API_KEY=client_vt_api)

        # Get file hash
        sha256 = hashlib.sha256(exe_bytes).hexdigest()
        print(f"SHA256 of file: {sha256}")

        # Extract features
        X = None
        vt_success = False
        with self.lock_vt_csv:
            X, vt_success = Get_X_from_EXE_bin(
                EXE_bin=exe_bytes,
                loaded_x_for_dll_api_section_Malware=feature_data,
                SHA256=sha256,
                Client_VT_instance=client_vt,
                SERVER_VT_CSV_MANAGER=self.vt_csv_manager
            )

        # Scale features
        X_scaled = scaler.transform(X)

        # Make prediction
        prediction = model.predict(X_scaled)
        print(f"Prediction: {prediction}")
        max_index = np.argmax(prediction)

        print(f"VT scan success: {vt_success}")

        # Update CSV if VT scan successful
        if vt_success:
            with self.lock_main_csv:
                csv_data, x_len, y_len = self.main_csv_manager.Open_and_Setting()
                
                if not any(row[1] == sha256 for row in csv_data):
                    # Save file
                    with open(f".\\{sha256}.exe", 'wb') as f:
                        f.write(exe_bytes)

                    # Add new entry
                    if self.main_csv_manager.Write_to_Csv(
                        [f".\\{sha256}.exe", sha256, str(label_data[max_index])]
                    ):
                        print("CSV updated successfully")
                else:
                    # Update existing entry
                    print("Updating existing entry")
                    if self.main_csv_manager.Rewrite_to_Csv(
                        Input_data=[f".\\{sha256}.exe", sha256, str(label_data[max_index])],
                        is_ALL_change=False,
                        specified_hint=sha256,
                        index_hint=1,
                        is_Append_column_data=False,
                        Rewrite_column=False,
                        columns_list_for_Rewrite_column=None,
                        is_Append_for_Rewrite_column=False
                    ):
                        print("CSV updated successfully")

        return (
            label_data, # Label names
            struct.pack('<f', float(prediction[0][max_index])), # Prediction confidence
            str(label_data[max_index]) # Predicted label
        )

    def Terminate_Instance(self) -> bool:
        # Terminate parallel threads
        if self.malware_thread:
            print("\nTerminating malware collection thread...")
            self.malware_thread_terminate = True
            self.malware_thread.join()
            print("Done!\n")

        if self.benign_thread:
            print("\nTerminating benign collection thread...")
            self.benign_thread_terminate = True
            self.benign_thread.join()
            print("Done!\n")

        return True

# Create instance
ai = AI_Instance(
    server_vt_api='please INPUT API here',
    vt_csv_path='VT_analysed.csv',
    main_csv_path='SHARE_ai_exe_dataset.csv', 
    save_index='idk2'
)

# Train model
ai.Start_Train(
    epoch=100,
    batch_size=2,
    patience=25
)

# Load sample for prediction
sample_exe = b''
with open("C:\\wget.exe", 'rb') as f:
    sample_exe = f.read()

# Make prediction
result = ai.Start_Prediction(
    exe_bytes=sample_exe,
    client_vt_api='please INPUT API here'
)

print(result)

while True:
    # Terminate threads when done
    ai.Terminate_Instance() # [v2.1]
    pass
