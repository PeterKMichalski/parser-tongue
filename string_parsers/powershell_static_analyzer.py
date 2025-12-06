# string_parsers/powershell_static_analyzer.py

import re
import logging
import base64
from collections import OrderedDict
import ast # For safely evaluating literal structures
import gzip # <-- NEW: For Gzip decompression
import io   # <-- NEW: For handling byte streams

logger = logging.getLogger(__name__)

# --- Regex Definitions ---
# (Existing regex patterns remain the same)
VAR_ASSIGN_REGEX = re.compile(r'(\$[A-Za-z0-9_]+)\s*=\s*([\'"])(.*?)\2')
VAR_TO_VAR_ASSIGN_REGEX = re.compile(r'(\$[A-Za-z0-9_]+)\s*=\s*(\$[A-Za-z0-9_]+)')
BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
URL_REGEX = re.compile(r'\b(?:https?|ftp)://[^\s/$.?#].[^\s"\']*|\bwww\.[^\s/$.?#].[^\s"\']*')
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b')
FILE_PATH_REGEX = re.compile(r'(?:[a-zA-Z]:|\\{1,2}|/|\.)(?:[\\/][\w\.\-\s()]+)+')
FILENAME_REGEX = re.compile(
    r'\b[\w\.\-\s()]+\.(?:exe|dll|ps1|bat|vbs|txt|log|zip|rar|7z|tmp|dat|sys|cab|inf|ini|scr|hta|js|jar|docm|xlsm|pptm)\b',
    re.IGNORECASE
)
SIMPLE_CONCAT_REGEX = re.compile(r'([\'"])(.*?)\1\s*\+\s*([\'"])(.*?)\3')
SIMPLE_FORMAT_REGEX = re.compile(r'([\'"])(.+?)\1\s*-f\s*((?:\'[^\']*\',?\s*)+)')
CHAR_DEC_REGEX = re.compile(r'\[char\]\s*\(([\d\s+\-*/()]+)\)|\[char\](\d+)', re.IGNORECASE)
CHAR_HEX_REGEX = re.compile(r'\[char\]\s*(?:\(\s*)?\[byte\]\s*(0x[0-9a-f]+)(?:\s*\))?', re.IGNORECASE)

# --- NEW: Regex for Gzip Decompression Patterns ---
# Looks for MemoryStream initialization with a byte array (often from Base64)
MEM_STREAM_INIT_REGEX = re.compile(r'\$([\w_]+)\s*=\s*\[System\.IO\.MemoryStream\]::new\(\[byte\[\]\]\s*\$([\w_]+)\)', re.IGNORECASE)
# Looks for GzipStream initialization and decompression call (simplified)
GZIP_DECOMPRESS_REGEX = re.compile(r'\[System\.IO\.Compression\.GzipStream\]::new\(\$([\w_]+),\s*\[System\.IO\.Compression\.CompressionMode\]::Decompress\)\s*\)\.Read', re.IGNORECASE)
# Alternative Gzip pattern using StreamReader
GZIP_STREAMREADER_REGEX = re.compile(r'\[System\.IO\.StreamReader\]::new\(\s*\[System\.IO\.Compression\.GzipStream\]::new\(\$([\w_]+),.*Decompress.*?\)\s*\)\.ReadToEnd\(\)', re.IGNORECASE)


class PowerShellStaticAnalyzer:
    parser_name = "PowerShell Static Analyzer"
    # Updated description
    parser_description = "Statically analyzes obfuscated PowerShell commands to beautify, resolve simple variables, decode Base64, simplify concatenations, decode char codes, decompress Gzip streams, and extract IOCs."

    def can_parse_string(self, input_string):
        """Checks if the string looks like PowerShell."""
        input_lower = input_string.lower()
        # Look for common PowerShell keywords or patterns
        if "powershell" in input_lower or \
           "iex" in input_lower or \
           "invoke-expression" in input_lower or \
           re.search(r'\$[A-Za-z]', input_string) or \
           re.search(r'\[char\]', input_string, re.IGNORECASE) or \
           "gzipstream" in input_lower: # Check for gzip
            return 85
        return 0

    def _safe_eval_math(self, expr):
        """Safely evaluate simple mathematical expressions using a restricted approach."""
        try:
            expr = expr.replace(" ", "")
            if not re.fullmatch(r'[\d+\-*/()]+', expr):
                raise ValueError("Expression contains unsafe characters")
            allowed_chars = "0123456789+-*/(). "
            if not all(c in allowed_chars for c in expr) or \
               re.search(r'[a-zA-Z_]', expr) or \
               '**' in expr:
                 raise ValueError("Expression contains disallowed characters or patterns")
            result = eval(expr, {'__builtins__': {}}, {})
            if isinstance(result, (int, float)):
                 return int(result)
            else:
                 raise ValueError("Evaluation did not result in a number")
        except Exception as e:
            logger.warning(f"Could not safely evaluate math expression '{expr}': {e}")
            return None

    # --- NEW: Helper for Gzip Decompression ---
    def _try_decompress_gzip(self, byte_data):
        """Attempts to decompress byte data using gzip."""
        if not byte_data:
            return None
        try:
            with io.BytesIO(byte_data) as compressed_stream:
                # Add check for gzip magic bytes
                if compressed_stream.read(2) != b'\x1f\x8b':
                    compressed_stream.seek(0) # Reset stream if not gzip
                    return None # Not Gzip data

                compressed_stream.seek(0) # Reset stream position
                with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as decompressed_stream:
                    decompressed_data = decompressed_stream.read()
                    
                    # Try to decode as text, otherwise return hex
                    try:
                        return decompressed_data.decode('utf-8', errors='ignore')
                    except Exception:
                        return decompressed_data.hex() # Return hex representation for binary data
        except Exception as e:
            logger.warning(f"Gzip decompression failed: {e}")
            return f"GZIP_DECOMPRESS_ERROR: {e}"


    def parse_string(self, input_string):
        """Performs multi-stage static analysis."""

        results = {'original_script': input_string}
        current_script = input_string
        # Store byte arrays decoded from Base64 for potential Gzip use
        decoded_byte_map = {}

        try:
            # --- Stage 0: Initial Cleanup ---
            current_script = re.sub(r'^(powershell\.exe|pwsh\.exe)\s*.*?(-c|-command|-e|-encodedcommand)\s+', '', current_script, flags=re.IGNORECASE).strip()
            current_script = re.sub(r'\s*;\s*', ';', current_script)
            current_script = re.sub(r'\s*=\s*', '=', current_script)
            current_script = re.sub(r'\s*\(\s*', '(', current_script)
            current_script = re.sub(r'\s*\)\s*', ')', current_script)
            current_script = re.sub(r'\s*\+\s*', '+', current_script)

            # --- Stage 1: Variable Collection ---
            commands = current_script.split(';')
            string_map = OrderedDict()
            var_map = OrderedDict()
            for cmd in commands:
                str_match = VAR_ASSIGN_REGEX.match(cmd)
                if str_match:
                    var_name, quote, value = str_match.groups()
                    string_map[var_name] = value
                    # --- Check if this string is Base64 and store bytes ---
                    if BASE64_REGEX.fullmatch(value):
                        try:
                             padding = '=' * (4 - (len(value) % 4))
                             decoded_bytes = base64.b64decode(value + padding)
                             decoded_byte_map[var_name] = decoded_bytes
                             # Also add the decoded string version to string_map for replacement
                             try:
                                 string_map[var_name] = decoded_bytes.decode('utf-8', errors='ignore')
                             except Exception:
                                 string_map[var_name] = str(decoded_bytes) # Fallback
                        except Exception as b64e:
                             logger.warning(f"Failed decoding base64 for {var_name}: {b64e}")
                    continue
                var_match = VAR_TO_VAR_ASSIGN_REGEX.match(cmd)
                if var_match:
                    var_name, assigned_var = var_match.groups()
                    var_map[var_name] = assigned_var
            results['initial_string_assignments'] = dict(string_map)
            results['initial_var_assignments'] = dict(var_map)

            # --- Stage 2: Variable Resolution Loop ---
            resolved_vars_this_pass = True
            passes = 0
            MAX_PASSES = 10
            while resolved_vars_this_pass and passes < MAX_PASSES and var_map:
                resolved_vars_this_pass = False
                vars_to_remove = []
                for var_name, assigned_var in list(var_map.items()):
                    if assigned_var in string_map:
                        string_map[var_name] = string_map[assigned_var]
                        # Propagate byte data if it exists
                        if assigned_var in decoded_byte_map:
                            decoded_byte_map[var_name] = decoded_byte_map[assigned_var]
                        vars_to_remove.append(var_name)
                        resolved_vars_this_pass = True
                for var_name in vars_to_remove:
                    del var_map[var_name]
                passes += 1
            if passes == MAX_PASSES and var_map:
                 logger.warning(f"Variable resolution exceeded max passes. Unresolved: {list(var_map.keys())}")
            results['resolved_string_map'] = dict(string_map)
            results['unresolved_var_map'] = dict(var_map)


            # --- Stage 2.5: Character Decoding ---
            decoded_script = current_script # Start fresh after cleanup
            changed_in_decode_pass = True
            decode_passes = 0
            MAX_DECODE_PASSES = 10

            while changed_in_decode_pass and decode_passes < MAX_DECODE_PASSES:
                changed_in_decode_pass = False
                script_before_pass = decoded_script
                # A. Decode Decimal
                def dec_replacer(match):
                    expr, num = match.groups()
                    val = self._safe_eval_math(expr) if expr else (int(num) if num else None)
                    return chr(val) if val is not None and 0 <= val <= 0x10FFFF else match.group(0)
                decoded_script = CHAR_DEC_REGEX.sub(dec_replacer, decoded_script)
                # B. Decode Hex
                def hex_replacer(match):
                    try: val = int(match.group(1), 16); return chr(val) if 0 <= val <= 0x10FFFF else match.group(0)
                    except Exception: return match.group(0)
                decoded_script = CHAR_HEX_REGEX.sub(hex_replacer, decoded_script)
                # --- Update variable map if decoding changed values ---
                # (This is complex, for now we rely on the loops)

                if decoded_script != script_before_pass:
                    changed_in_decode_pass = True
                decode_passes += 1
            if decode_passes == MAX_DECODE_PASSES and changed_in_decode_pass:
                logger.warning("Character decoding loop reached max passes.")
            current_script = decoded_script


            # --- Stage 3: Simplification (String Concatenation) ---
            simplified_script = current_script
            changed_in_pass = True
            simplify_passes = 0
            MAX_SIMPLIFY_PASSES = 10
            while changed_in_pass and simplify_passes < MAX_SIMPLIFY_PASSES:
                changed_in_pass = False
                original_script_before_pass = simplified_script
                # A. Simplify 'str1' + 'str2'
                def concat_replacer(match):
                    q, s1, _, s2 = match.groups()
                    return f"{q}{s1 or ''}{s2 or ''}{q}"
                simplified_script = SIMPLE_CONCAT_REGEX.sub(concat_replacer, simplified_script)
                # TODO: Implement -f simplification
                if simplified_script != original_script_before_pass:
                    changed_in_pass = True
                simplify_passes += 1
            if simplify_passes == MAX_SIMPLIFY_PASSES and changed_in_pass:
                 logger.warning("Simplification loop reached max passes.")
            current_script = simplified_script


            # --- Stage 4: Final Variable Replacement & Beautification ---
            beautified_lines = []
            final_script_for_ioc = ""
            commands = current_script.split(';')
            vars_to_replace = sorted(string_map.keys(), key=len, reverse=True)
            for cmd in commands:
                 processed_cmd = cmd.strip()
                 if not processed_cmd: continue
                 is_assignment = False; assignment_var = None
                 for var in vars_to_replace:
                     if re.match(r'^\s*' + re.escape(var) + r'\s*=', processed_cmd):
                         is_assignment = True; assignment_var = var; break
                 temp_cmd = processed_cmd
                 replacement_value = "" # Define outside loop
                 if is_assignment:
                     parts = temp_cmd.split('=', 1)
                     if len(parts) == 2:
                         left, right = parts
                         for var in vars_to_replace:
                             if var != assignment_var:
                                 escaped_var = re.escape(var)
                                 replacement_value = string_map[var].replace('\\', '\\\\')
                                 right = re.sub(r'(?<![\w\$])' + escaped_var + r'(?![\w])',
                                                f"'{replacement_value}'", right)
                         temp_cmd = f"{left}={right}"
                 else:
                     for var in vars_to_replace:
                          escaped_var = re.escape(var)
                          replacement_value = string_map[var].replace('\\', '\\\\')
                          temp_cmd = re.sub(r'(?<![\w\$])' + escaped_var + r'(?![\w])',
                                            f"'{replacement_value}'", temp_cmd)
                 beautified_lines.append(temp_cmd)
                 final_script_for_ioc += temp_cmd + ";"
            results['beautified_script'] = "\n".join(beautified_lines)


            # --- Stage 5: Gzip Decompression (NEW) ---
            decompressed_payloads = []
            # Look for MemoryStream($byte_var)
            mem_stream_matches = MEM_STREAM_INIT_REGEX.findall(final_script_for_ioc)
            stream_vars = {} # Map stream var name to the byte var name
            for stream_var, byte_var in mem_stream_matches:
                 stream_vars[f"${stream_var}"] = f"${byte_var}"

            # Look for GzipStream($stream_var).Read or StreamReader(GzipStream($stream_var)).ReadToEnd
            gzip_read_matches = GZIP_DECOMPRESS_REGEX.findall(final_script_for_ioc)
            gzip_reader_matches = GZIP_STREAMREADER_REGEX.findall(final_script_for_ioc)
            
            potential_gzip_streams = set()
            for stream_var_match in gzip_read_matches + gzip_reader_matches:
                 potential_gzip_streams.add(f"${stream_var_match}")

            for stream_var in potential_gzip_streams:
                if stream_var in stream_vars:
                    byte_var_name = stream_vars[stream_var]
                    if byte_var_name in decoded_byte_map:
                         logger.info(f"Attempting Gzip decompression on data from {byte_var_name}")
                         decompressed = self._try_decompress_gzip(decoded_byte_map[byte_var_name])
                         if decompressed:
                             decompressed_payloads.append({
                                 'source_variable': byte_var_name,
                                 'decompressed_content': decompressed
                             })
                    else:
                         logger.warning(f"Found Gzip pattern using {stream_var} but couldn't find byte data for {byte_var_name}")
                else:
                    logger.warning(f"Found Gzip pattern using {stream_var} but couldn't find its MemoryStream initialization")
            results['decompressed_gzip_payloads'] = decompressed_payloads


            # --- Stage 6: Indicator Extraction ---
            results['extracted_urls'] = sorted(list(set(URL_REGEX.findall(final_script_for_ioc))))
            results['extracted_ips'] = sorted(list(set(IP_REGEX.findall(final_script_for_ioc))))
            results['extracted_paths'] = sorted(list(set(FILE_PATH_REGEX.findall(final_script_for_ioc))))
            results['extracted_filenames'] = sorted(list(set(FILENAME_REGEX.findall(final_script_for_ioc))))
            base64_found = BASE64_REGEX.findall(final_script_for_ioc)
            decoded_base64 = []
            for b64_str in base64_found:
                 # Only add if not already handled in decoded_byte_map (avoid duplication)
                 is_already_in_byte_map = False
                 for byte_var, byte_content in decoded_byte_map.items():
                      # This check is imperfect, assumes direct assignment was found
                      if string_map.get(byte_var) == b64_str:
                           is_already_in_byte_map = True
                           break
                 if is_already_in_byte_map: continue

                 try: # Standard Base64 decoding logic
                     padding = '=' * (4 - (len(b64_str) % 4))
                     valid = re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', b64_str)
                     if not valid: continue
                     decoded_bytes = base64.b64decode(b64_str + padding)
                     try: decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
                     except Exception: decoded_string = str(decoded_bytes)
                     decoded_base64.append({'original': b64_str, 'decoded': decoded_string})
                 except Exception as decode_error:
                     if 'padding' not in str(decode_error).lower() and 'incorrect' not in str(decode_error).lower():
                         logger.warning(f"Failed B64 decode '{b64_str[:20]}...': {decode_error}")
                     decoded_base64.append({'original': b64_str, 'decoded': f'DECODE_ERROR: {decode_error}'})
            results['decoded_base64'] = decoded_base64

            results['parse_status'] = 'SUCCESS'

        except Exception as e:
            logger.error(f"Error during PowerShell static analysis: {e}", exc_info=True)
            results['parse_status'] = 'ERROR'
            results['error_message'] = str(e)
            if 'beautified_script' not in results:
                 results['beautified_script'] = "\n".join(input_string.split(';'))

        
        # --- NEW: Add Disclaimer ---
        results['DISCLAIMER'] = "Static analysis is best-effort. Manually validate all findings."

        return results

