# This file provides parsing capabilities for JSON and JSONL files.

import logging
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

# Get a logger instance
logger = logging.getLogger(__name__)

class JsonParser:
    """
    This is a flexible parser for JSON and JSONL files.
    It auto-detects the file type (full JSON or line-by-line)
    and flattens nested JSON objects into flat CSV columns.
    """

    # --- PARSER METADATA ---
    parser_name = "JSON/JSONL Parser"
    parser_description = "Parses .json (full file) or .jsonl (line-by-line) files."
    supported_extensions = ['.json', '.jsonl']

    def can_parse(self, filepath, file_content_sample):
        """
        Returns a confidence score (0-100) of how likely this
        parser is to handle the given file.
        """
        # A valid JSON or JSONL file will almost always start with { or [
        sample_text = file_content_sample.decode('utf-8', 'ignore').strip()
        
        if sample_text.startswith('{') or sample_text.startswith('['):
            return 100 # High confidence
            
        return 0

    def _flatten_json(self, obj_to_flatten, parent_key='', separator='.'):
        """
        Recursively flattens a nested dictionary or list.
        e.g., {"user": {"name": "test"}} -> {"user.name": "test"}
        e.g., {"actions": [{"type": "login"}]} -> {"actions.0.type": "login"}
        """
        flat_dict = {}

        # Case 1: It's a dictionary
        if isinstance(obj_to_flatten, dict):
            if not obj_to_flatten: # Handle empty dict
                if parent_key:
                    flat_dict[parent_key] = {}
                return flat_dict
                
            for key, value in obj_to_flatten.items():
                new_key = f"{parent_key}{separator}{key}" if parent_key else key
                # Recurse
                flat_dict.update(self._flatten_json(value, new_key, separator=separator))
        
        # Case 2: It's a list
        elif isinstance(obj_to_flatten, list):
            if not obj_to_flatten: # Handle empty list
                if parent_key:
                    flat_dict[parent_key] = []
                return flat_dict
                
            for i, item in enumerate(obj_to_flatten):
                new_key = f"{parent_key}{separator}{i}"
                # Recurse
                flat_dict.update(self._flatten_json(item, new_key, separator=separator))
        
        # Case 3: It's a primitive (base case for the recursion)
        else:
            # --- NEW: Check if the primitive is a JSON string ---
            if isinstance(obj_to_flatten, str):
                stripped_value = obj_to_flatten.strip()
                # Check if it *looks* like an embedded JSON object or list
                if (stripped_value.startswith('{') and stripped_value.endswith('}')) or \
                   (stripped_value.startswith('[') and stripped_value.endswith(']')):
                    
                    try:
                        # It looks like JSON, try to parse it
                        nested_obj = json.loads(stripped_value)
                        
                        # If successful, recurse!
                        # We pass the *original* parent_key to flatten the new data
                        # into the current level.
                        flat_dict.update(self._flatten_json(nested_obj, parent_key, separator=separator))
                        return flat_dict # IMPORTANT: Return after update
                        
                    except json.JSONDecodeError:
                        # It looked like JSON, but wasn't.
                        # Fall through and just store the original string.
                        pass
            # --- END NEW LOGIC ---

            # If it's not a parsable string, or not a string at all,
            # just store the primitive value.
            key_to_use = parent_key if parent_key else 'value'
            flat_dict[key_to_use] = obj_to_flatten
            
        return flat_dict


    def _get_records_from_object(self, full_data, is_interactive):
        """
        Internal helper to find the list of records within a JSON object.
        Returns a list of tuples: [(source_key_name, list_of_records)]
        """
        
        # Find all keys that contain lists (our candidates)
        list_keys = [key for key, value in full_data.items() if isinstance(value, list)]
        
        if not list_keys:
            # No lists found. Treat the entire object as one record.
            logger.warning("JSON object has no lists. Parsing the full object as a single record.")
            # Return as a list of tuples for consistent processing
            return [ (None, [full_data]) ]

        # --- Handle Interactive Mode ---
        if is_interactive:
            if len(list_keys) == 1:
                # Only one choice, so we auto-select it.
                key = list_keys[0]
                logger.info(f"JSON is a dict. Auto-selecting key '{key}' as record list.")
                return [ (key, full_data[key]) ]
            else:
                # --- This is the new interactive prompt ---
                print("\n[!] This JSON file is an object with multiple lists.")
                print("    Please choose the key that contains the records you want to parse:")
                for i, key in enumerate(list_keys, 1):
                    sample_count = len(full_data[key])
                    print(f"      [{i}] {key}  ({sample_count} items)")
                
                # --- NEW "Parse All" option ---
                all_option_num = len(list_keys) + 1
                print(f"      [{all_option_num}] Parse All Lists")
                
                try:
                    choice_str = input(f"    Enter your choice [1-{all_option_num}]: ")
                    choice_idx = int(choice_str) - 1
                    
                    if 0 <= choice_idx < len(list_keys):
                        # User picked one list
                        chosen_key = list_keys[choice_idx]
                        logger.info(f"User selected key: '{chosen_key}'")
                        return [ (chosen_key, full_data[chosen_key]) ]
                    elif choice_idx == (all_option_num - 1):
                        # User picked "Parse All"
                        logger.info("User selected 'Parse All Lists'.")
                        return [(key, full_data[key]) for key in list_keys]
                    else:
                        raise ValueError("Invalid choice")
                        
                except (ValueError, KeyboardInterrupt, EOFError):
                    print("\n[!] Invalid choice or operation cancelled. Aborting parse.")
                    logger.warning("User failed to select a JSON key.")
                    return None # Signal to abort
        
        # --- Handle Non-Interactive (Batch) Mode ---
        else:
            # In batch mode, we will parse ALL lists found, as it's safer
            # than just picking the first one.
            logger.info(f"JSON is a dict. Auto-selecting all {len(list_keys)} lists for batch mode.")
            return [(key, full_data[key]) for key in list_keys]

    def parse(self, filepath, is_batch=False):
        """
        Parses the file and returns a list of dictionaries.
        Tries to parse as a full JSON file first, then falls back
        to line-by-line JSONL parsing.
        """
        parsed_data = []
        filepath_str = str(filepath)
        
        is_interactive = not is_batch
        
        # 1. --- Try to parse as a single, full JSON file ---
        try:
            with open(filepath_str, 'r', encoding='utf-8', errors='ignore') as f:
                full_data = json.load(f)
            
            logger.info(f"Successfully parsed {filepath.name} as a full JSON file.")
            
            records_to_parse_map = [] # Will be a list of tuples
            is_full_file_parse = False # Flag to track if we're parsing a single object

            if isinstance(full_data, list):
                records_to_parse_map = [ (None, full_data) ] # No source key
            elif isinstance(full_data, dict):
                records_to_parse_result = self._get_records_from_object(full_data, is_interactive)
                if records_to_parse_result is None:
                    return [] # User cancelled
                records_to_parse_map = records_to_parse_result
            else:
                records_to_parse_map = [ (None, [full_data]) ] # single primitive
                is_full_file_parse = True
        
            
            # --- Process the found records (Full File Mode) ---
            for source_key, record_list in records_to_parse_map:
                for record_obj in record_list:
                    
                    if is_full_file_parse and not (isinstance(record_obj, (dict, list))):
                        flat_record = {'value': record_obj}
                    else:
                        flat_record = self._flatten_json(record_obj)

                    # Add traceability columns
                    if isinstance(record_obj, (dict, list)):
                        try:
                            flat_record['raw_record_json'] = json.dumps(record_obj)
                        except TypeError:
                             flat_record['raw_record_json'] = str(record_obj)
                    else:
                        flat_record['raw_record_json'] = str(record_obj)
                    
                    flat_record['parse_status'] = 'SUCCESS'
                    
                    # Add source_key if we parsed from multiple lists
                    if source_key:
                        flat_record['source_json_key'] = source_key
                    
                    timestamp = flat_record.get('timestamp') or flat_record.get('Timestamp') or flat_record.get('date')
                    flat_record['Timestamp_UTC'] = self._normalize_time(timestamp)
                    
                    parsed_data.append(flat_record)
            
            return parsed_data

        except json.JSONDecodeError:
            logger.info(f"Not a full JSON file. Falling back to JSONL (line-by-line) mode for {filepath.name}.")
        except Exception as e:
            logger.error(f"Error during full JSON parse of {filepath.name}: {e}", exc_info=True)
            return []

        # 2. --- Fallback: Parse as JSONL (line-by-line) ---
        try:
            with open(filepath_str, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    record = {
                        'Timestamp_UTC': None,
                        'parse_status': 'UNPARSED',
                        'raw_log': line
                    }
                    
                    try:
                        json_obj = json.loads(line)
                        
                        flat_record = self._flatten_json(json_obj)
                        record.update(flat_record)
                        record['parse_status'] = 'SUCCESS'
                        
                        timestamp = record.get('timestamp') or record.get('Timestamp') or record.get('date')
                        record['Timestamp_UTC'] = self._normalize_time(timestamp)

                    except json.JSONDecodeError:
                        # --- THIS IS THE CRITICAL CHANGE ---
                        # The line is not valid JSON. Let's try to see if it's
                        # an *escaped string* containing JSON, using your logic.
                        try:
                            # 1. Un-escape common characters
                            # This is safer than your original regex
                            cleaned_line = line.encode().decode('unicode_escape')
                            
                            # 2. Try to parse *that*
                            json_obj = json.loads(cleaned_line)

                            # 3. If successful, flatten and add
                            flat_record = self._flatten_json(json_obj)
                            record.update(flat_record)
                            record['parse_status'] = 'SUCCESS_CLEANED'
                            
                            timestamp = record.get('timestamp') or record.get('Timestamp') or record.get('date')
                            record['Timestamp_UTC'] = self._normalize_time(timestamp)

                        except Exception:
                            # It was truly just a malformed line.
                            logger.warning(f"Failed to parse JSONL line: {line}")
                        # --- END CRITICAL CHANGE ---
                    
                    parsed_data.append(record)

        except Exception as e:
            logger.error(f"Error parsing file {filepath.name} in JSONL mode: {e}", exc_info=True)
            
        return parsed_data

    # --- HELPER METHODS ---
    def _normalize_time(self, timestamp_str):
        """
        Converts a custom timestamp string to a standardized 
        UTC ISO-8601 string (YYYY-MM-DDTHH:MM:SSZ).
        """
        if not timestamp_str:
            return None
            
        dt = None

        try:
            if isinstance(timestamp_str, str):
                timestamp_str = timestamp_str.replace('Z', '+00:00')
            dt = datetime.fromisoformat(str(timestamp_str))
        except (ValueError, TypeError):
            try:
                dt = datetime.strptime(str(timestamp_str), '%Y-%m-%d %H:%M:%S')
                dt = dt.replace(tzinfo=timezone.utc) # Assume UTC
            except (ValueError, TypeError):
                try:
                    dt = datetime.fromtimestamp(float(timestamp_str), tz=timezone.utc)
                except (ValueError, TypeError):
                    logger.warning(f"Could not parse timestamp: {timestamp_str}")
                    return str(timestamp_str) 

        # --- Standardize the output ---
        if dt:
            try:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dt_utc = dt.astimezone(timezone.utc)
                dt_no_micros = dt_utc.replace(microsecond=0)
                return dt_no_micros.isoformat().replace('+00:00', 'Z')
            except Exception as e:
                logger.warning(f"Error standardizing timestamp for '{timestamp_str}': {e}")

        return str(timestamp_str)

