'''
    CSV file handler class that provides functionality to:
    - Read column count, row count, column names and row data
    - Write data to CSV files
'''
import numpy as np
import pandas as pd

class CsvHandler:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.df = None
        self.num_cols = None 
        self.num_rows = None
        self.parsed_data = None

    def read_csv(self) -> tuple[list, int, int]:
        """
        Reads and parses the CSV file
        
        Returns:
            Tuple containing:
            - List of parsed CSV data (column headers + rows)
            - Number of columns
            - Number of rows
        """
        self.df = pd.read_csv(self.csv_path)
        columns = list(self.df.columns.values)
        self.num_cols = len(columns)
        
        # Parse column data
        column_data = []
        for col_name in columns:
            col_values = []
            for value in self.df[col_name]:
                col_values.append(value)
            column_data.append(col_values)
            
            if len(col_values) > 0:
                self.num_rows = len(col_values)

        # Transpose data and add headers
        self.parsed_data = list(map(list, zip(*column_data))) 
        self.parsed_data.insert(0, columns)

        return self.parsed_data, self.num_cols, self.num_rows

    def write_row(self, row_data: list) -> bool:
        """
        Writes a new row to the CSV file
        
        Args:
            row_data: List of values for the new row
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.parsed_data is None:
            self.parsed_data, self.num_cols, self.num_rows = self.read_csv()

        if self.num_cols is None:
            print("Must call read_csv() first")
            return False

        if len(row_data) != self.num_cols:
            print("Row length does not match number of columns")
            return False

        self.parsed_data.append(row_data)
        df = pd.DataFrame(self.parsed_data)
        df.to_csv(self.csv_path, header=False, index=False)
        return True

    def append_row(self, row_data: list) -> bool:
        """
        Appends a row to the CSV file
        
        Args:
            row_data: List of values to append
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.write_row(row_data)

    def get_row(self, search_value: str, col_index: int) -> list:
        """
        Gets a row where the value in the specified column matches search_value
        
        Args:
            search_value: Value to search for
            col_index: Index of column to search in
            
        Returns:
            List containing the matching row, or None if not found
        """
        if self.parsed_data is None:
            self.parsed_data, self.num_cols, self.num_rows = self.read_csv()

        if self.num_cols is None:
            print("Must call read_csv() first")
            return None

        for row in self.parsed_data:
            if row[col_index] == search_value:
                return list(row)
        return None

    def update_csv(self, new_data: list, update_all: bool = False, 
                  search_value: str = None, col_index: int = None,
                  append_cols: bool = False, update_headers: bool = False,
                  new_headers: list = None, append_headers: bool = None) -> bool:
        """
        Updates data in the CSV file
        
        Args:
            new_data: New data to write
            update_all: Whether to update all rows
            search_value: Value to search for when updating specific row
            col_index: Column index to search in
            append_cols: Whether to append columns instead of replacing
            update_headers: Whether to update column headers
            new_headers: New header values
            append_headers: Whether to append headers
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.parsed_data is None:
            self.parsed_data, self.num_cols, self.num_rows = self.read_csv()

        if self.num_cols is None:
            print("Must call read_csv() first") 
            return False

        if update_headers:
            if new_headers is not None and append_headers is not None:
                self.update_headers(new_headers, append_headers)

        for i, row in enumerate(self.parsed_data):
            if i == 0:  # Skip headers
                continue

            if not append_cols:
                if not update_all:
                    if search_value is None or col_index is None:
                        return False
                    if row[col_index] == search_value:
                        self.parsed_data.insert(i, new_data)
                        self.parsed_data.pop(i+1)
                else:
                    self.parsed_data.insert(i, new_data)
                    self.parsed_data.pop(i+1)
            else:
                if not update_all:
                    if search_value is None or col_index is None:
                        return False
                    if row[col_index] == search_value:
                        row.extend(new_data)
                        self.parsed_data[i] = row
                else:
                    row.extend(new_data)
                    self.parsed_data[i] = row

        df = pd.DataFrame(self.parsed_data)
        df.to_csv(self.csv_path, header=False, index=False)
        return True

    def update_headers(self, new_headers: list, append: bool) -> None:
        """
        Updates the CSV column headers
        
        Args:
            new_headers: New header values
            append: Whether to append or replace headers
        """
        if self.parsed_data is None:
            self.parsed_data, self.num_cols, self.num_rows = self.read_csv()

        if self.num_cols is None:
            print("Must call read_csv() first")
            return

        if append:
            if isinstance(new_headers, list):
                self.parsed_data[0].extend(new_headers)
            else:
                self.parsed_data[0].append(new_headers)
        else:
            self.parsed_data[0] = new_headers