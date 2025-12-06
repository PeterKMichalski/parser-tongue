# string_parsers/powershell_advanced_analyzer.py

import re
import logging
from collections import OrderedDict
import base64
import gzip # Added for potential Gzip in decoded payloads
import io   # Added for potential Gzip in decoded payloads

logger = logging.getLogger(__name__)

# --- Regex Definitions ---
VAR_FIND_REGEX = re.compile(r'\$([A-Za-z0-9_]+)')
VAR_ASSIGN_START_REGEX = re.compile(r'(\$[A-Za-z0-9_]+)\s*=')
# Updated assignment regex to better capture quoted strings or other variables
# Group 1: Variable Name | Group 2: Quote Char | Group 3: String Value | Group 4: Var Value | Group 5: Other Value
VAR_ASSIGN_REGEX = re.compile(r'(\$[A-Za-z0-9_]+)\s*=\s*(?:([\'"])(.*?)\2|(\$[A-Za-z0-9_]+)|(.+))')

URL_REGEX = re.compile(r'\b(?:https?|ftp)://[^\s/$.?#].[^\s"\']*|\bwww\.[^\s/$.?#].[^\s"\']*')
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b')
FILE_PATH_REGEX = re.compile(r'(?:[a-zA-Z]:|\\{1,2}|/|\.)(?:[\\/][\w\.\-\s()]+)+')
FILENAME_REGEX = re.compile(
    r'\b[\w\.\-\s()]+\.(?:exe|dll|ps1|bat|vbs|txt|log|zip|rar|7z|tmp|dat|sys|cab|inf|ini|scr|hta|js|jar|docm|xlsm|pptm)\b',
    re.IGNORECASE
)
# Regex for simple format operator: '{0}{1}' -f 'val1', '$var2'
# Group 1: Opening Quote | Group 2: Format String | Group 3: Args String
SIMPLE_FORMAT_OP_REGEX = re.compile(r'([\'"])(\{.*?\})\1\s*-f\s*(.+)', re.IGNORECASE)
# Ensure SIMPLE_CONCAT_REGEX is defined
SIMPLE_CONCAT_REGEX = re.compile(r'([\'"])(.*?)\1\s*\+\s*([\'"])(.*?)\3')
# --- Re-added BASE64_REGEX ---
BASE64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
# --- Regex for Character Decoding ---
CHAR_DEC_REGEX = re.compile(r'\[char\]\s*\(([\d\s+\-*/()]+)\)|\[char\](\d+)', re.IGNORECASE)
CHAR_HEX_REGEX = re.compile(r'\[char\]\s*(?:\(\s*)?\[byte\]\s*(0x[0-9a-f]+)(?:\s*\))?', re.IGNORECASE)


class PowerShellAdvancedAnalyzer:
    parser_name = "PowerShell Experimental Analyzer"
    # Updated description
    parser_description = ("WARNING: Experimental & potentially fragile. Attempts to resolve ALL variables, "
                          "simplify basic concatenations and format operators, and decode/feed back Base64/Gzip payloads. "
                          "May break on complex scripts. Use PowerShellStaticAnalyzer for safer analysis.")

    def can_parse_string(self, input_string):
        """Checks if the string looks like PowerShell."""
        # Same check as the static analyzer
        input_lower = input_string.lower()
        if "powershell" in input_lower or \
           "iex" in input_lower or \
           "invoke-expression" in input_lower or \
           re.search(r'\$[A-Za-z]', input_string):
            return 75
        return 0

    # --- Helper for safe math eval (from static analyzer) ---
    def _safe_eval_math(self, expr):
        """Safely evaluate simple mathematical expressions."""
        try:
            expr = expr.replace(" ", "")
            if not re.fullmatch(r'[\d+\-*/()]+', expr): return None
            allowed = "0123456789+-*/(). "
            if not all(c in allowed for c in expr) or re.search(r'[a-zA-Z_]', expr) or '**' in expr: return None
            # Use limited builtins for safety
            result = eval(expr, {'__builtins__': {}}, {})
            return int(result) if isinstance(result, (int, float)) else None
        except Exception: return None

    # --- Helper for Gzip (from static analyzer) ---
    def _try_decompress_gzip(self, byte_data):
        """Attempts Gzip decompression."""
        if not byte_data: return None
        try:
            with io.BytesIO(byte_data) as compressed_stream:
                # Check magic bytes
                if compressed_stream.read(2) != b'\x1f\x8b': return None
                compressed_stream.seek(0)
                with gzip.GzipFile(fileobj=compressed_stream, mode='rb') as decompressed_stream:
                    decompressed_data = decompressed_stream.read()
                    try: return decompressed_data.decode('utf-8', errors='ignore')
                    except Exception: return decompressed_data.hex()
        except Exception: return None # Suppress errors, just return None if fails

    def _try_decode_base64(self, b64_str):
        """Decodes Base64, returns bytes or None."""
        try:
            # Clean potential surrounding quotes/spaces before decoding
            b64_str = b64_str.strip().strip("'\"")
            padding = '=' * (4 - (len(b64_str) % 4))
            # More strict validation
            if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', b64_str + padding): return None
            return base64.b64decode(b64_str + padding)
        except Exception:
            return None

    def _recursive_replace(self, script, var_map, max_depth=10):
        """Recursively replaces variables until no changes occur or depth limit reached."""
        if max_depth <= 0:
            logger.warning("Max variable replacement depth reached.")
            return script

        changed = False
        new_script = script
        # Replace longest variables first to avoid partial replacements
        for var in sorted(var_map.keys(), key=len, reverse=True):
            escaped_var = re.escape(var)
            replacement_val = var_map[var]
            # Escape backslashes in replacement value for re.sub
            safe_replacement_val = replacement_val.replace('\\', '\\\\')

            # Use regex boundaries to avoid replacing parts of words/variables
            # (?<![\w$.]) - Negative lookbehind: Not preceded by word char, $, or .
            # (?![\w])   - Negative lookahead: Not followed by word char
            new_script_temp = re.sub(r'(?<![\w$.])' + escaped_var + r'(?![\w])',
                                     safe_replacement_val, new_script)
            if new_script_temp != new_script:
                changed = True
                new_script = new_script_temp

        if changed:
            return self._recursive_replace(new_script, var_map, max_depth - 1)
        else:
            return new_script

    def parse_string(self, input_string):
        """Performs multi-stage static analysis."""
        results = {'original_script': input_string}
        current_script = input_string
        # Keep track of fully resolved string values
        resolved_string_map = {}

        try:
            # --- Stage 0: Initial Cleanup ---
            current_script = re.sub(r'^(powershell\.exe|pwsh\.exe)\s*.*?(-c|-command|-e|-encodedcommand)\s+', '', current_script, flags=re.IGNORECASE).strip()
            # Clean spaces around ;=()+ (more conservative)
            current_script = re.sub(r'\s*([;=()+])\s*', r'\1', current_script)
            # Remove backticks used for line continuation
            current_script = current_script.replace('`', '')


            # --- Combined Loop for Resolution and Simplification ---
            MAX_MAIN_LOOPS = 15 # Safety break for combined loops
            main_loops = 0
            script_changed_in_loop = True

            while script_changed_in_loop and main_loops < MAX_MAIN_LOOPS:
                script_changed_in_loop = False
                script_at_loop_start = current_script
                main_loops += 1
                logger.debug(f"--- Starting Analysis Loop {main_loops} ---")

                # --- Stage 1: Collect Assignments (in each loop) ---
                commands = current_script.split(';')
                assignments_this_loop = {} # Holds all assignments found in this pass

                for cmd in commands:
                    cmd = cmd.strip()
                    if not cmd: continue

                    # Use the more flexible assignment regex
                    assign_match = VAR_ASSIGN_REGEX.match(cmd)
                    if assign_match:
                        var_name, quote, str_val, var_val, other_val = assign_match.groups()
                        if str_val is not None: # $var = 'string'
                            assignments_this_loop[var_name] = f"{quote}{str_val}{quote}"
                            resolved_string_map[var_name] = str_val # Store the raw string value
                        elif var_val: # $a = $b
                            assignments_this_loop[var_name] = var_val
                        elif other_val: # $a = <something else>
                            assignments_this_loop[var_name] = other_val.strip()
                        continue # Skip further processing for assignments for now

                logger.debug(f"Assignments found: {assignments_this_loop}")

                # --- Stage 2: Attempt Resolution ---
                resolved_in_pass = True
                resolve_passes = 0
                MAX_PASSES = 10 # Inner loop limit
                temp_resolved_map = resolved_string_map.copy() # Start with known strings

                while resolve_passes < MAX_PASSES and resolved_in_pass: # Inner loop like before
                    resolve_passes += 1
                    resolved_in_pass = False
                    for var, value in list(assignments_this_loop.items()):
                        if var in temp_resolved_map: continue # Already resolved to string

                        # Is the value another variable?
                        if value in temp_resolved_map:
                            # Resolve $a = $b where $b is known string
                            temp_resolved_map[var] = temp_resolved_map[value]
                            resolved_in_pass = True
                            # Remove var from assignments_this_loop to prevent re-processing?
                            # Could be complex if var is reassigned later. For now, just update map.
                        # TODO: Add check for simple math/concat here?

                resolved_string_map = temp_resolved_map # Update main map
                logger.debug(f"Resolved strings after pass {main_loops}: {resolved_string_map}")


                # --- Stage 3: Replace known variables in the *current* script ---
                script_after_replace = self._recursive_replace(current_script, resolved_string_map)
                if script_after_replace != current_script:
                    logger.debug("Script changed after variable replacement.")
                    current_script = script_after_replace
                    # Don't set script_changed_in_loop = True here, let simplification do it


                # --- Stage 4: Simplification (Concatenation & Format Operator) ---
                script_before_simplify = current_script
                # A. Simplify 'str1'+'str2' iteratively
                while True:
                    original_len = len(current_script)
                    def concat_replacer(match):
                        q1, s1, q2, s2 = match.groups() # Use 4 groups now
                        # Check if quotes match or handle mixed quotes if necessary
                        # For simplicity, assume same quotes or handle potential issues
                        return f"{q1}{s1 or ''}{s2 or ''}{q1}" # Reconstruct with first quote type
                    # Use the SIMPLE_CONCAT_REGEX defined at the top
                    current_script = SIMPLE_CONCAT_REGEX.sub(concat_replacer, current_script)
                    if len(current_script) == original_len: # Stop if no changes
                        break

                # B. Simplify basic "{0}{1}" -f 'val1', '$var2' iteratively
                while True:
                    original_len = len(current_script)
                    def format_replacer(match):
                        quote_char, f_string_inner, args_str = match.groups()
                        try:
                            # Attempt to parse args string more robustly
                            args = []
                            # Split args carefully, respecting quotes
                            current_arg = ""
                            in_quotes = False
                            quote_type = None
                            paren_depth = 0 # Handle potential nested calls in args
                            for char in args_str:
                                if char == '(' : paren_depth += 1
                                elif char == ')' : paren_depth -= 1

                                if char in ('\'', '"') and not in_quotes and paren_depth == 0:
                                    in_quotes = True
                                    quote_type = char
                                    current_arg += char
                                elif char == quote_type and in_quotes and paren_depth == 0:
                                    in_quotes = False
                                    current_arg += char
                                elif char == ',' and not in_quotes and paren_depth == 0:
                                    args.append(current_arg.strip())
                                    current_arg = ""
                                    quote_type = None
                                else:
                                    current_arg += char
                            args.append(current_arg.strip()) # Add the last arg

                            resolved_args = []
                            can_resolve = True
                            for arg in args:
                                arg_strip = arg.strip("'\"")
                                if arg.startswith('$') and arg in resolved_string_map:
                                    resolved_args.append(resolved_string_map[arg])
                                elif (arg.startswith('\'') and arg.endswith('\'')) or \
                                     (arg.startswith('"') and arg.endswith('"')):
                                    resolved_args.append(arg_strip)
                                else:
                                    # Might be a number, bool, null, or complex expression - cannot resolve safely here
                                    can_resolve = False
                                    break

                            if can_resolve:
                                result_str = f_string_inner
                                for i, res_arg in enumerate(resolved_args):
                                    # Escape regex special chars in replacement
                                    safe_res_arg = res_arg.replace('{','{{').replace('}','}}')
                                    result_str = result_str.replace(f'{{{i}}}', safe_res_arg)
                                return f"{quote_char}{result_str}{quote_char}" # Return with original quotes
                            else:
                                return match.group(0) # Cannot resolve, return original

                        except Exception as e:
                            logger.warning(f"Failed simple format op simplify: {e}")
                            return match.group(0) # Return original on error
                    current_script = SIMPLE_FORMAT_OP_REGEX.sub(format_replacer, current_script)
                    if len(current_script) == original_len: # Stop if no changes
                         break

                if current_script != script_before_simplify:
                     logger.debug("Script changed after simplification.")
                     script_changed_in_loop = True


                # --- Stage 5: Decode Base64/Gzip discovered IN THIS LOOP ---
                # Find Base64 strings *in the current script state*
                base64_found_now = BASE64_REGEX.findall(current_script) # <-- Use BASE64_REGEX here
                new_commands_from_decode = []
                processed_b64 = set() # Avoid reprocessing the same string

                for b64_str in base64_found_now:
                    if b64_str in processed_b64: continue
                    processed_b64.add(b64_str)

                    decoded_bytes = self._try_decode_base64(b64_str)
                    if decoded_bytes:
                        # Try Gzip?
                        decompressed = self._try_decompress_gzip(decoded_bytes)
                        content_to_check = None
                        if decompressed:
                            # Assume decompressed content is the primary payload
                           content_to_check = decompressed if isinstance(decompressed, str) else None
                        else:
                            # Try decoding Base64 as text
                            try: content_to_check = decoded_bytes.decode('utf-8', errors='ignore')
                            except Exception: pass

                        # Heuristic: Does it look like more PowerShell?
                        if content_to_check and ('$' in content_to_check or ';' in content_to_check or 'Invoke-' in content_to_check): # Broader check
                            # Basic check to avoid adding huge binary data misinterpreted as script
                            if len(content_to_check) < 20000: # Increased limit
                                logger.info("Found potential PowerShell in decoded content. Adding for next loop.")
                                # Sanitize before adding back?
                                new_commands_from_decode.append(content_to_check.strip())
                                script_changed_in_loop = True # Force another loop

                # Inject newly found commands back into the script for the next loop
                if new_commands_from_decode:
                    current_script += ";" + ";".join(new_commands_from_decode)
                    # Clean up again after adding new commands
                    current_script = re.sub(r'\s*;\s*', ';', current_script).strip(';')


                # --- Loop Check ---
                if current_script == script_at_loop_start:
                    logger.debug("No changes detected in loop, exiting.")
                    script_changed_in_loop = False # Break loop if script is stable


            if main_loops == MAX_MAIN_LOOPS and script_changed_in_loop:
                logger.warning("Main analysis loop reached max iterations. Deobfuscation might be incomplete.")

            # --- Final Beautification ---
            final_script_parts = []
            final_commands = current_script.split(';')
            for cmd in final_commands:
                cmd_strip = cmd.strip()
                if cmd_strip:
                     # Remove resolved simple assignments like $a='val'; more carefully
                     is_simple_resolved_assignment = False
                     assign_match = VAR_ASSIGN_REGEX.match(cmd_strip)
                     if assign_match:
                          var_name, quote, str_val, var_val, other_val = assign_match.groups()
                          # If it was a string assignment AND it's in our final map
                          if str_val is not None and var_name in resolved_string_map and resolved_string_map[var_name] == str_val:
                               is_simple_resolved_assignment = True

                     if not is_simple_resolved_assignment:
                          final_script_parts.append(cmd_strip)

            # Join with newlines for readability
            results['beautified_script'] = "\n".join(final_script_parts)

            # --- Final Indicator Extraction on the *final* script ---
            final_script_text = results['beautified_script'] # Use the beautified one
            results['extracted_urls'] = sorted(list(set(URL_REGEX.findall(final_script_text))))
            results['extracted_ips'] = sorted(list(set(IP_REGEX.findall(final_script_text))))
            results['extracted_paths'] = sorted(list(set(FILE_PATH_REGEX.findall(final_script_text))))
            results['extracted_filenames'] = sorted(list(set(FILENAME_REGEX.findall(final_script_text))))

            results['parse_status'] = 'SUCCESS_EXPERIMENTAL'

        except Exception as e:
            logger.error(f"Error during Advanced PowerShell analysis: {e}", exc_info=True)
            results['parse_status'] = 'ERROR_EXPERIMENTAL'
            results['error_message'] = str(e)
            if 'beautified_script' not in results:
                 results['beautified_script'] = "\n".join(input_string.split(';')) # Fallback beautify

        # Add Disclaimer
        results['DISCLAIMER'] = ("EXPERIMENTAL: This parser uses fragile methods to resolve all variables and simplify constructs. "
                                 "Results may be incomplete or incorrect. Always manually validate findings.")

        return results

