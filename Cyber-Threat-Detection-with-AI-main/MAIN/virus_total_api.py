'''
    The number of key values in the final json to be analyzed varies by file extension!

    [EXE]:
            type_description // file type
            tlsh // ?
            vhash // file hash
            type_tags // {}
            creation_date
            names
            last_modification_date
            type_tag
            times_submitted
            total_votes
            size
            popular_threat_classification
            authentihash
            detectiteasy
            last_submission_date
            reputation
            trid
            sha256
            type_extension
            tags
            last_analysis_date
            unique_sources
            first_submission_date
            sha1
            ssdeep
            md5
            pe_info
            magic
            last_analysis_stats
            last_analysis_results
'''

import json, hashlib, requests, struct

# Process:
# 1. Calculate file hash (sha256) and check if scan history exists
# 2. If no history, submit file to API endpoint
# 3. If status is queued, wait and check again

class VirusTotal_class():
    def __init__(self, API_KEY:str ):
        self.API = API_KEY

    def Start_Scan(self, Path:str = None, Binary_DATA:bytes = None, Binary_DATA_SHA256:str = None) -> ( bool, list, bytes): # returns (success, results, server_bytes)
        self.DATA:bytes

        hashed = ''
        if(Path):
            with open(Path, 'rb') as f:
                self.DATA = f.read()
            hashed = hashlib.sha256(self.DATA).hexdigest()  # Calculate SHA256 of file
        elif(Binary_DATA):
            self.DATA = Binary_DATA
            hashed = Binary_DATA_SHA256
        else:
            print("Please provide either a file path or binary data")
            return False,None,None

        # First check scan history using hash
        status = requests.get(f"https://www.virustotal.com/api/v3/files/{hashed}", headers={"x-apikey": self.API})
        self.json_data = json.loads(status.text)
        print(f"Scan history check -> {self.json_data}")
        try:
            '''
               If file cannot be read, meaning no previous scan history exists
            '''
            if ( "NotFoundError" != str(self.json_data["error"]["code"])):
                print("File has previous scan history")
                raise "a"
            else:
                '''
                    Submit file to get analysis ID.
                    Access analysis results using ID (only after queued state)
                '''
                status = requests.post("https://www.virustotal.com/api/v3/files", headers={"x-apikey": self.API},files={"file": self.DATA})  # Get analysis ID
                json_new_data = json.loads(status.text)
                print(json_new_data)
                analysis_id = str(json_new_data["data"]["id"])

                status = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",headers={"x-apikey": self.API})
                json_new_data_analyse = json.loads(status.text)
                print(json_new_data_analyse)

                if ("queued" == str(json_new_data_analyse["data"]["attributes"]["status"])):

                    is_queued = True
                    while (is_queued):
                        status = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                              headers={"x-apikey": self.API})
                        json_new_data_analyse = json.loads(status.text)
                        if ("queued" == str(json_new_data_analyse["data"]["attributes"]["status"])):
                            print(f"Still queued. {json_new_data_analyse}")
                        else:
                            is_queued = False
                status = requests.get(f"https://www.virustotal.com/api/v3/files/{hashed}", headers={"x-apikey": self.API})
                self.json_data = json.loads(status.text) # Now contains previous analysis info
        except:
            print("Exception!")
            self.json_data # Already contains previous analysis info

        finally:
            '''
                Begin extraction
            '''
            print(self.json_data)

            result = self.Start_Analyse( hashed, self.json_data  ) # Analyze result json (returns list)

            '''
                Create length-based byte structure for Rust server
            '''
            result_but_length_Based_Bytes__For__Server = self.Build_Vt_result_for_Server(result) # list -> bytes

            '''
                Verify?
            '''
            self.already_Raw_DATA_parsing_for_TEST( result_but_length_Based_Bytes__For__Server )

            return True, result, result_but_length_Based_Bytes__For__Server

    def Start_Analyse(self, FILE_SHA256: str, data) -> list:

        '''
            Return_Bytes_results info:
            [0] -> File_SHA256 (for verification)
            [1] -> last_analysis_list
            [2] -> last_analysis_stats_list
            [3] -> total_votes_list
        '''
        Return_Bytes_results = []

        print(f" data -> {data['data']}")
        print(f" data/type -> {data['data']['type']}\n")

        print(f" data/attributes -> {data['data']['attributes']}")
        print(f" data/attributes/last_analysis_results -> {data['data']['attributes']['last_analysis_results']}")

        '''
            [0]
            Add file SHA256
        '''

        if data['data']['attributes']['sha256'] == data['data']['id'] == FILE_SHA256:
            Return_Bytes_results.append([FILE_SHA256])
        else:
            return None

        print(f"\n\n\nReturn_Bytes_results -> {Return_Bytes_results}")

        '''
            [1]
            <last_analysis_results> - 2D
            [0]: Engine name
            [1]: Detection category (malicious status)
            [2]: Detection result
        '''
        last_analysis_list = [['last_analysis_results']]  # Contains engine results (for AI training)

        for index, Analyser_Name in enumerate(data['data']['attributes']['last_analysis_results']):
            category = data['data']['attributes']['last_analysis_results'][Analyser_Name]['category']
            results = str(data['data']['attributes']['last_analysis_results'][Analyser_Name]['result']) if \
            data['data']['attributes']['last_analysis_results'][Analyser_Name]['result'] != None else "None"

            last_analysis_list.append([Analyser_Name, category, results])

        Return_Bytes_results.append(last_analysis_list)
        print("last_analysis_list -> ", last_analysis_list)

        '''
            [2]
            <last_analysis_stats>
            [0]malicious
            [1]suspicious
            [2]undetected
            [3]harmless
            [4]timeout
            [5]confirmed-timeout
            [6]failure
            [7]type-unsupported
            
            [Recent issue]
            Rust server cannot handle column names with "-". Solution: Replace "-" with "_"
        '''
        last_analysis_stats_list = [['last_analysis_stats_list']]  # Contains total scores
        for index, Analyse_stats in enumerate(data['data']['attributes']['last_analysis_stats']):
            last_analysis_stats_list.append( [Analyse_stats.replace("-","_"), str(data['data']['attributes']['last_analysis_stats'][Analyse_stats])] )

        Return_Bytes_results.append(last_analysis_stats_list)
        print('last_analysis_stats_list -> ', last_analysis_stats_list)

        '''
            [3] Results_Vote - Overall malware votes
            
            [0]harmless
            [1]malicious
        '''
        total_votes_list = [['total_votes']]  # Contains total scores (key included due to Rust server parsing)
        for index, Analyse_total_votes in enumerate(data['data']['attributes']['total_votes']):
            total_votes_list.append(
                [Analyse_total_votes, str(data['data']['attributes']['total_votes'][Analyse_total_votes])])
        Return_Bytes_results.append(total_votes_list)

        '''
            [final]
        '''
        print(f"[Final]Return_Bytes_results -> {Return_Bytes_results}")

        return Return_Bytes_results

    def Build_Vt_result_for_Server(self, DATA) -> bytes:
        '''
            Create length-based reputation results for server
            {"_vt_"-signature 4bytes} + {length 4bytes + Raw_DATA (dynamic)} + {"_END"}
        '''
        Return_Result_Bytes = '_vt_'.encode()

        for index, data in enumerate(DATA):
            '''
                1 case:
                    data -> [['SHA256'] - 2 ] - 1 (2D total)
                2 case:
                    data -> [ ['','']-3,['','']... -2  ] - 1 (3D total)
            '''
            if len(data) > 1:  # Has more 2D?
                for index2, data2 in enumerate(data):
                    print(data2)
                    for index3, data3 in enumerate(data2):

                        try:
                            '''
                                data3 can be str or int. Convert all to bytes here
                            '''
                            if isinstance(data3, str):
                                data3:bytes = data3.encode()
                            elif isinstance(data3, int):
                                data3:bytes = self.int_to_4bytes( int(data3) )
                            else:
                                data3:bytes = bytes(data3)
                        except:
                            print("Cannot process this type for server data!")
                            data3:bytes = b'None'

                        '''
                            Continuously accumulate {4byte length} + {Raw_DATA} to main bytes data
                        '''
                        Return_Result_Bytes = self.Build_length_andthen_Raw_DATA(Return_Result_Bytes, data3)

            elif len(data) == 1:  # Is 1D?
                data = data[0]  # Unpack 1D
                data = data.encode() if isinstance(data, str) else bytes(data)
                Return_Result_Bytes = self.Build_length_andthen_Raw_DATA(Return_Result_Bytes, data)
            else:
                print("VT - Parsing error!")
                return b''

        Return_Result_Bytes += "_END".encode()
        return Return_Result_Bytes

    # Returns {length-4bytes} + {Raw_Data} for length-based structure
    def Build_length_andthen_Raw_DATA(self, Return_Result_Bytes: bytes, DATA: bytes) -> bytes:
        Return_Result_Bytes += self.int_to_4bytes(len(DATA))
        Return_Result_Bytes += DATA
        return Return_Result_Bytes

    # Method to verify server data was created correctly
    def already_Raw_DATA_parsing_for_TEST(self, Return_Result_Bytes: bytes) -> bool:
        try:
            start_index = 0
            last_index = 4
            Vt_signature = Return_Result_Bytes[start_index:last_index].decode()
            print(f"Vt_signature -> {Vt_signature}")
            start_index = last_index
            last_index = last_index + 4

            while True:
                if Return_Result_Bytes[start_index: last_index] == b'_END':
                    break

                length = self.Bytes_to_int(Return_Result_Bytes[start_index: last_index])
                start_index = last_index
                last_index = last_index + length
                Raw_DATA = Return_Result_Bytes[start_index: last_index]
                start_index = last_index
                last_index = last_index + 4
                print(
                    f"length -> {length} / RAW_DATA -> {Raw_DATA.decode() if isinstance(Raw_DATA, str) else Raw_DATA}")
        except:
            return False
        return True

    # Converters
    def int_to_4bytes(self, integer: int) -> bytes:
        return struct.pack('<I', integer)

    def Bytes_to_int(self, Data: bytes) -> int:
        return int((struct.unpack('<I', Data))[0])


'''url = 'C:\\DriverView.exe'
VirusTotal_class("please INPUT API here").Start_Scan(Path=url)'''
