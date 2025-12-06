# core/engine.py

import logging
import sys
import pandas as pd
from pathlib import Path
import re # For sanitizing parser names
import json # For printing string parser results

# V2 Update
from . import parser_loader
import multiprocessing
import functools

# Configure a basic logger
logger = logging.getLogger(__name__)

# --- MULTIPROCESSING HELPER ---
# This MUST be a top-level function, not a class method.
def _process_file_wrapper(file_path, engine_instance, force_parser, output_dir):
    """
    A wrapper function to be called by the multiprocessing pool.
    """
    try:
        # 1. Determine parser
        chosen_parser = None
        if force_parser:
            if force_parser in engine_instance.file_parsers:
                chosen_parser = engine_instance.file_parsers[force_parser]
            else:
                logger.warning(f"Forced parser '{force_parser}' not found for {file_path.name}. Skipping.")
                return (False, f"Parser '{force_parser}' not found.")
        else:
            # Run detection. Note: This is NOT interactive in batch mode.
            status, result = engine_instance._detect_parser(file_path)

            if status == 'SUCCESS':
                chosen_parser = result
            elif status == 'CONFLICT':
                chosen_parser = result[0]
                logger.warning(f"Conflict for {file_path.name}, auto-selecting '{chosen_parser.parser_name}'.")
            else:
                logger.warning(f"No parser found for {file_path.name} (Status: {status}). Skipping.")
                return (False, f"No parser match (Status: {status})")

        # 2. Determine output path
        # V2.1: Sanitize parser name
        parser_key = re.sub(r'[\\/:"*?<>|]+', '', chosen_parser.parser_name.lower().replace(" ", "_"))
        # V2.1: Use file_path.stem to remove original extension
        output_name = f"{file_path.stem}_{parser_key}.csv"

        output_file_path = None
        if output_dir:
            output_file_path = Path(output_dir) / output_name
        else:
            output_file_path = file_path.parent / output_name

        # 3. Get unique filename
        output_file_path = engine_instance._get_unique_filepath(output_file_path)

        # 4. Run the actual parse task
        # V2: Pass is_batch=True
        return engine_instance._run_parse_task(file_path, chosen_parser, output_file_path, is_batch=True)

    except Exception as e:
        logger.error(f"Unhandled error in worker for {file_path.name}: {e}", exc_info=True)
        return (False, str(e))

# --- END HELPER ---


class ParserEngine:
    """
    The main engine for Parser Tongue. Orchestrates parser loading,
    file detection, and parsing for both files and strings.
    """

    def __init__(self, verbose=False):
        """
        Initializes the engine, sets up logging, and loads parsers.
        """
        self._setup_logging(verbose)
        logger.info("Initializing ParserEngine...")

        # V2 Update: Load both types of parsers from the correct locations
        self.file_parsers = parser_loader.load_file_parsers()
        self.string_parsers = parser_loader.load_string_parsers()

        if not self.file_parsers:
            logger.warning("No file/log parsers were loaded. Check the /log_parsers directory.")
        else:
            logger.info(f"Successfully loaded {len(self.file_parsers)} file/log parsers.")

        if not self.string_parsers:
            logger.warning("No string parsers were loaded. Check the /string_parsers directory.")
        else:
            logger.info(f"Successfully loaded {len(self.string_parsers)} string parsers.")

    def _setup_logging(self, verbose):
        """Sets up the console and file logging."""

        # Check if handlers are already added (to prevent duplicates)
        root_logger = logging.getLogger()
        if root_logger.hasHandlers():
            # If we're in a worker process, just set the level
            console_level = logging.DEBUG if verbose else logging.INFO
            for handler in root_logger.handlers:
                if isinstance(handler, logging.StreamHandler):
                    handler.setLevel(console_level)
            return

        root_logger.setLevel(logging.DEBUG)

        # --- File Logger (Always DEBUG) ---
        try:
            file_handler = logging.FileHandler('parser_tongue.log')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            # Handle cases where log file can't be written
            print(f"Warning: Could not open log file 'parser_tongue.log'. Error: {e}")

        # --- Console Logger (INFO or DEBUG) ---
        console_handler = logging.StreamHandler(sys.stdout)
        console_level = logging.DEBUG if verbose else logging.INFO
        console_handler.setLevel(console_level)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # --- V2: Renamed and new list methods ---
    def list_file_parsers(self, filter_term=None):
        """Prints a formatted list of all loaded FILE parsers."""
        self._list_parsers_helper(self.file_parsers, "File / Log Parsers", filter_term)

    def list_string_parsers(self, filter_term=None):
        """Prints a formatted list of all loaded STRING parsers."""
        self._list_parsers_helper(self.string_parsers, "String Parsers", filter_term)

    def _list_parsers_helper(self, parsers, title, filter_term=None):
        """Generic helper to print a filtered list of parsers."""
        if not parsers:
            logger.warning(f"No {title} to list.")
            print(f"[INFO] No {title} were found.")
            return

        if filter_term and filter_term != '_LIST_ALL_':
            logger.info(f"Filtering {title} with term: '{filter_term}'")
            filter_term = filter_term.lower()
        else:
            filter_term = None

        print(f"\nAvailable {title}:")

        match_count = 0
        for name_key, parser in parsers.items():

            # Build searchable content
            content_to_search = [
                name_key,
                parser.parser_name.lower(),
                parser.parser_description.lower(),
            ]
            if hasattr(parser, 'supported_extensions'):
                content_to_search.extend([ext.lower() for ext in parser.supported_extensions])

            # Check for a match
            display_this = False
            if not filter_term:
                display_this = True
            else:
                if any(filter_term in content for content in content_to_search):
                    display_this = True

            if display_this:
                match_count += 1
                print("-" * 60)
                print(f"Name Key: {name_key}")
                try:
                    print(f"Parser Name: {parser.parser_name}")
                    print(f"Description: {parser.parser_description}")
                    if hasattr(parser, 'supported_extensions'):
                        print(f"Extensions: {parser.supported_extensions}")
                except Exception as e:
                    logger.error(f"Error reading metadata from parser: {name_key} ({e})")

        print("-" * 60)
        if filter_term:
            print(f"\nFound {match_count} parser(s) matching '{filter_term}'.")
        else:
            print(f"\nFound {match_count} total parser(s).")

    # --- File Parsing Methods ---

    def parse_file(self, filepath, output_path=None, force_parser=None):
        """Manages the full parsing process for a single file."""
        logger.info(f"Starting to process single file: {filepath}")

        file_path_obj = Path(filepath)
        if not file_path_obj.exists() or not file_path_obj.is_file():
            logger.error(f"File not found or is not a file: {filepath}")
            print(f"[ERROR] File not found: {filepath}")
            return

        chosen_parser = None

        if force_parser:
            if force_parser in self.file_parsers:
                chosen_parser = self.file_parsers[force_parser]
                logger.info(f"User forced file parser: '{chosen_parser.parser_name}'")
            else:
                logger.error(f"Forced file parser '{force_parser}' not found.")
                print(f"[ERROR] Parser '{force_parser}' not found.")
                print("Use --list-parsers to see available parsers.") # <-- Corrected reference
                return

        else:
            status, result = self._detect_parser(file_path_obj)

            if status == 'SUCCESS':
                parser = result
                print(f"\n[!] Auto-detect recommends: '{parser.parser_name}'")
                try:
                    choice = input("    Use this parser? [Y/n]: ").strip().lower()
                    if choice == 'n':
                        logger.info("User rejected auto-detected parser.")
                        print("Operation cancelled by user.")
                        return
                    chosen_parser = parser
                except (KeyboardInterrupt, EOFError):
                    print("\nOperation cancelled.")
                    return

            elif status == 'CONFLICT':
                print("\n[!] Conflict detected. Multiple parsers are confident:")
                conflicts = result
                for i, parser in enumerate(conflicts, 1):
                    print(f"  [{i}] {parser.parser_name}: {parser.parser_description}")

                try:
                    choice_str = input(f"Please choose a parser [1-{len(conflicts)}]: ")
                    choice_idx = int(choice_str) - 1
                    if 0 <= choice_idx < len(conflicts):
                        chosen_parser = conflicts[choice_idx]
                        logger.info(f"User resolved conflict, chose: '{chosen_parser.parser_name}'")
                    else:
                        raise ValueError("Invalid choice")
                except (ValueError, KeyboardInterrupt, EOFError):
                    print("\nInvalid choice or operation cancelled.")
                    logger.info("User failed to resolve conflict.")
                    return

            elif status == 'NO_MATCH':
                logger.error(f"No matching parser found for {filepath}")
                # V2.1: Smarter error message
                if not file_path_obj.suffix:
                    print(f"[ERROR] No matching parser could be found for '{file_path_obj.name}' (file has no extension).")
                    print("        Try forcing a parser with --parser <parser_key>")
                else:
                    print(f"[ERROR] No matching parser could be found for file extension '{file_path_obj.suffix}'.")
                    print("        Use --list-parsers to see all available parsers and their extensions.") # <-- Corrected reference
                return

        if chosen_parser:
            final_output_path = None

            if output_path:
                final_output_path = Path(output_path)
                # Check if user gave a directory for a single file parse
                if final_output_path.is_dir():
                    logger.warning("User specified an output directory for a single file. Auto-generating filename.")
                    parser_key = re.sub(r'[\\/:"*?<>|]+', '', chosen_parser.parser_name.lower().replace(" ", "_"))
                    output_name = f"{file_path_obj.stem}_{parser_key}.csv"
                    final_output_path = final_output_path / output_name
            else:
                # Auto-generate path in same directory as input
                parser_key = re.sub(r'[\\/:"*?<>|]+', '', chosen_parser.parser_name.lower().replace(" ", "_"))
                output_name = f"{file_path_obj.stem}_{parser_key}.csv"
                final_output_path = file_path_obj.parent / output_name

            # Get a unique filename
            final_output_path = self._get_unique_filepath(Path(final_output_path))

            # V2: Pass is_batch=False
            self._run_parse_task(file_path_obj, chosen_parser, final_output_path, is_batch=False)
        else:
            logger.error("Parser selection failed unexpectedly.")

    def parse_directory(self, dir_path, output_dir=None, force_parser=None):
        """Manages parsing for an entire directory using multiprocessing."""
        logger.info(f"Starting to process directory: {dir_path}")

        dir_path_obj = Path(dir_path)
        if not dir_path_obj.exists() or not dir_path_obj.is_dir():
            logger.error(f"Directory not found or is not a directory: {dir_path}")
            print(f"[ERROR] Directory not found: {dir_path}")
            return

        output_dir_obj = None
        if output_dir:
            output_dir_obj = Path(output_dir)
            if not output_dir_obj.exists():
                logger.info(f"Output directory not found. Creating: {output_dir}")
                try:
                    output_dir_obj.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    logger.error(f"Could not create output directory: {e}", exc_info=True)
                    print(f"[ERROR] Could not create output directory: {e}")
                    return
        else:
            # Default to saving in the input directory
            output_dir_obj = dir_path_obj

        files_to_process = [f for f in dir_path_obj.rglob('*') if f.is_file()]

        if not files_to_process:
            logger.warning(f"No files found in directory: {dir_path}")
            print(f"[INFO] No files found in: {dir_path}")
            return

        logger.info(f"Found {len(files_to_process)} files to process.")

        task_with_args = functools.partial(
            _process_file_wrapper,
            engine_instance=self,
            force_parser=force_parser,
            output_dir=output_dir_obj
        )

        num_cores = multiprocessing.cpu_count()
        logger.info(f"Starting multiprocessing pool with {num_cores} workers.")

        success_count = 0
        fail_count = 0

        try:
            with multiprocessing.Pool(processes=num_cores) as pool:
                results = pool.map(task_with_args, files_to_process)

                for res_success, res_msg in results:
                    if res_success:
                        success_count += 1
                    else:
                        fail_count += 1
        except Exception as e:
            logger.error(f"Multiprocessing pool failed: {e}", exc_info=True)
            print(f"[FATAL] Multiprocessing error. Check log for details.")
            return

        logger.info("--- Directory Processing Complete ---")
        logger.info(f"Successfully parsed: {success_count} files")
        logger.info(f"Failed or skipped:  {fail_count} files")
        print("\n[INFO] Directory processing complete.")
        print(f"Successfully parsed: {success_count} files")
        print(f"Failed or skipped:  {fail_count} files")

    def _detect_parser(self, filepath):
        """Internal method to run auto-detection logic for file parsers."""

        logger.debug(f"Detecting parser for {filepath}...")

        try:
            file_ext = filepath.suffix.lower()
            with open(filepath, 'rb') as f:
                file_sample = f.read(2048)
        except Exception as e:
            logger.error(f"Failed to read file {filepath} for detection: {e}")
            return ('NO_MATCH', None)

        candidate_parsers = []
        for name, parser in self.file_parsers.items():
            exts = parser.supported_extensions
            if not exts or file_ext in exts or (not file_ext and '' in exts):
                candidate_parsers.append(parser)

        if not candidate_parsers:
            logger.info(f"No parsers found with support for extension '{file_ext}'.")
            return ('NO_MATCH', None)

        scores = {}
        logger.debug(f"Checking {len(candidate_parsers)} candidate(s) for {filepath.name}")
        for parser in candidate_parsers:
            try:
                score = parser.can_parse(filepath, file_sample)
                if score > 0:
                    scores[parser] = score
            except Exception as e:
                logger.warning(f"Parser '{parser.parser_name}' failed 'can_parse': {e}")

        if not scores:
            logger.info(f"No parser confidently identified {filepath.name}.")
            return ('NO_MATCH', None)

        sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        best_parser, best_score = sorted_scores[0]

        MIN_CONFIDENCE = 70
        if best_score < MIN_CONFIDENCE:
            logger.info(f"No parser met minimum confidence threshold for {filepath.name}.")
            return ('NO_MATCH', None)

        conflicts = [best_parser]
        for parser, score in sorted_scores[1:]:
            if score == best_score:
                conflicts.append(parser)
            else:
                break

        if len(conflicts) > 1:
            logger.warning(f"Conflict detected for {filepath.name}. {len(conflicts)} parsers have score {best_score}.")
            return ('CONFLICT', conflicts)

        logger.info(f"Auto-detect success: '{best_parser.parser_name}' chosen for {filepath.name} (Score: {best_score})")
        return ('SUCCESS', best_parser)

    def _get_unique_filepath(self, output_path):
        """
        Checks if a file exists. If so, appends a number.
        e.g., file.csv -> file_1.csv -> file_2.csv
        """
        parent = output_path.parent
        ext = output_path.suffix
        stem = output_path.name[:-len(ext)]

        counter = 1
        new_path = output_path

        while new_path.exists():
            new_stem = f"{stem}_{counter}"
            new_path = parent / f"{new_stem}{ext}"
            counter += 1

        return new_path

    def _run_parse_task(self, file_path, chosen_parser, output_path, is_batch=False):
        """
        The actual workhorse. Parses one file and saves the output.
        """
        logger.info(f"Parsing '{file_path.name}' with '{chosen_parser.parser_name}'...")
        total_lines = 0
        success_lines = 0
        unparsed_lines = 0

        try:
            data_list = chosen_parser.parse(file_path, is_batch=is_batch)

            if not data_list:
                logger.warning(f"Parser '{chosen_parser.parser_name}' returned no data for {file_path.name}.")
                print(f"INFO: Parser '{chosen_parser.parser_name}' returned no data for {file_path.name}.")
                return (True, "No data extracted.")

            total_lines = len(data_list)
            try:
                if total_lines > 0 and 'parse_status' in data_list[0]:
                    for row in data_list:
                        if row.get('parse_status') == 'SUCCESS':
                            success_lines += 1
                        else:
                            unparsed_lines += 1
                else:
                    success_lines = total_lines
            except Exception:
                success_lines = total_lines

            df = pd.DataFrame(data_list)

            if 'Timestamp_UTC' in df.columns:
                all_columns = df.columns.tolist()
                all_columns.pop(all_columns.index('Timestamp_UTC'))
                new_column_order = ['Timestamp_UTC'] + all_columns
                df = df[new_column_order]

            df.to_csv(output_path, index=False)

            summary_msg = f"Successfully saved parsed data to {output_path}"
            logger.info(summary_msg)
            print(f"\n[SUCCESS] {summary_msg}")

            if unparsed_lines > 0:
                stats_msg = f"    └─ Stats: Total Lines: {total_lines} | Parsed: {success_lines} | Unparsed (raw): {unparsed_lines}"
            else:
                stats_msg = f"    └─ Stats: Total Lines: {total_lines} | All lines parsed successfully."

            logger.info(stats_msg)
            print(stats_msg)

            return (True, str(output_path))

        except Exception as e:
            logger.error(f"FATAL ERROR parsing {file_path.name}: {e}", exc_info=True)
            print(f"\n[ERROR] Failed to parse {file_path.name}. See log for details.")
            return (False, str(e))

    # --- V2: String Parsing Methods ---

    def run_string_parsing_engine(self, input_string, force_parser=None):
        """Manages the full parsing process for a single string."""
        logger.info(f"Starting to process string: '{input_string[:50]}...'")

        chosen_parser = None

        if force_parser:
            if force_parser in self.string_parsers:
                chosen_parser = self.string_parsers[force_parser]
                logger.info(f"User forced string parser: '{chosen_parser.parser_name}'")
            else:
                logger.error(f"Forced string parser '{force_parser}' not found.")
                print(f"[ERROR] String parser '{force_parser}' not found.")
                print("Use --list-string-parsers to see available parsers.") # <-- Corrected reference
                return
        else:
            status, result = self._detect_string_parser(input_string)

            if status == 'SUCCESS':
                chosen_parser = result
                print(f"[INFO] Auto-detected string parser: '{chosen_parser.parser_name}'")
            elif status == 'CONFLICT':
                chosen_parser = result[0]
                logger.warning(f"String parser conflict, defaulting to '{chosen_parser.parser_name}'")
                print(f"[INFO] Multiple parsers matched. Defaulting to: '{chosen_parser.parser_name}'")
            elif status == 'NO_MATCH':
                logger.error(f"No matching string parser found for: '{input_string[:50]}...'")
                print("[ERROR] No matching string parser could be found.")
                return

        if chosen_parser:
            try:
                result_dict = chosen_parser.parse_string(input_string)

                # --- NEW: Print beautified script separately ---
                beautified_script = result_dict.pop('beautified_script', None)

                if beautified_script:
                    print("\n--- Beautified Script ---")
                    print(beautified_script) # This prints with real newlines
                    print("-------------------------\n")

                # Print the rest of the results as JSON
                print("--- Analysis Results ---")
                print(json.dumps(result_dict, indent=4))
                print("------------------------")
                # --- END NEW ---

            except Exception as e:
                logger.error(f"String parser '{chosen_parser.parser_name}' failed: {e}", exc_info=True)
                print(f"[ERROR] Parser failed during execution: {e}")
        else:
            logger.error("String parser selection failed unexpectedly.")

    def _detect_string_parser(self, input_string):
        """Internal method to run auto-detection for string parsers."""
        scores = {}
        for name, parser in self.string_parsers.items():
            try:
                score = parser.can_parse_string(input_string)
                if score > 0:
                    scores[parser] = score
            except Exception as e:
                logger.warning(f"String parser '{parser.parser_name}' failed 'can_parse_string': {e}")

        if not scores:
            return ('NO_MATCH', None)

        sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        best_parser, best_score = sorted_scores[0]

        MIN_CONFIDENCE = 50
        if best_score < MIN_CONFIDENCE:
            return ('NO_MATCH', None)

        conflicts = [best_parser]
        for parser, score in sorted_scores[1:]:
            if score == best_score:
                conflicts.append(parser)
            else:
                break

        if len(conflicts) > 1:
            return ('CONFLICT', conflicts)

        return ('SUCCESS', best_parser)

    # --- V2.1: NEW Method ---
    def parse_string_from_file(self, filepath, force_parser=None):
        """
        Reads an entire file into a single string and passes it
        to the string parsing engine.
        """
        logger.info(f"Reading file '{filepath}' to parse as a single string...")

        file_path_obj = Path(filepath)
        if not file_path_obj.exists() or not file_path_obj.is_file():
            logger.error(f"File not found or is not a file: {filepath}")
            print(f"[ERROR] File not found: {filepath}")
            return

        try:
            with open(file_path_obj, 'r', encoding='utf-8', errors='ignore') as f:
                content_string = f.read()

            if not content_string:
                logger.warning(f"File '{filepath}' is empty.")
                print("[INFO] Input file is empty.")
                return

            # Now, just call the string parsing engine
            self.run_string_parsing_engine(content_string, force_parser)

        except Exception as e:
            logger.error(f"Failed to read string file {filepath}: {e}", exc_info=True)
            print(f"[ERROR] Failed to read file: {e}")

