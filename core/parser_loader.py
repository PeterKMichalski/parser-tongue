# core/parser_loader.py

import importlib.util
import inspect
from pathlib import Path
import sys
import logging
import re

logger = logging.getLogger(__name__)

# --- Constants ---
# Base directory is the parent of 'core'
BASE_DIR = Path(__file__).parent.parent
PARSERS_DIR = BASE_DIR / "log_parsers" # <-- RENAMED
STRING_PARSERS_DIR = BASE_DIR / "string_parsers"
TEMPLATE_FILE = Path(__file__).parent / "templates.py"

# --- Add parser directories to sys.path ---
# This is CRUCIAL for multiprocessing/pickling.
# Check if paths already exist to avoid duplicates
if str(PARSERS_DIR) not in sys.path:
    sys.path.append(str(PARSERS_DIR))
if str(STRING_PARSERS_DIR) not in sys.path:
    sys.path.append(str(STRING_PARSERS_DIR))

def _load_parsers_from_dir(directory, class_attributes):
    """
    Generic helper to load parsers from a given directory.
    """
    parsers = {}
    logger.debug(f"Attempting to load parsers from directory: {directory}") # <-- Added Debug
    if not directory.exists():
        logger.warning(f"Parser directory not found, creating: {directory}")
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Could not create parser directory {directory}: {e}")
            return parsers

    for f in directory.glob("*.py"):
        logger.debug(f"Checking file: {f.name}") # <-- Added Debug
        if f.name.startswith("_") or "template" in f.name:
            logger.debug(f"Skipping file (private or template): {f.name}") # <-- Added Debug
            continue

        parser_name_key = f.stem
        logger.debug(f"Attempting to import module: {parser_name_key}") # <-- Added Debug
        try:
            # Import by name (thanks to sys.path update)
            module = importlib.import_module(parser_name_key)
            logger.debug(f"Successfully imported module: {parser_name_key}") # <-- Added Debug

            found_class_in_module = False # <-- Added Debug flag
            for name, obj in inspect.getmembers(module, inspect.isclass):
                logger.debug(f"Inspecting class in {parser_name_key}: {name}") # <-- Added Debug
                # Check if the class has all the required attributes
                missing_attrs = [attr for attr in class_attributes if not hasattr(obj, attr)]
                if not missing_attrs:
                    logger.debug(f"Found potential parser class: {name} with all required attributes.") # <-- Added Debug
                    found_class_in_module = True # <-- Added Debug flag
                    try:
                        parser_instance = obj()
                        # Use the parser_name as the key
                        key = parser_instance.parser_name.lower().replace(" ", "_")
                        key = re.sub(r'[\\/:"*?<>|]+', '', key) # Sanitize key
                        parsers[key] = parser_instance
                        logger.info(f"Successfully loaded parser '{parser_instance.parser_name}' with key '{key}' from {f.name}") # <-- Changed to INFO
                    except Exception as e:
                        logger.warning(f"Failed to instantiate parser class {name} in {f.name}: {e}")
                else:
                     logger.debug(f"Class {name} skipped. Missing attributes: {missing_attrs}") # <-- Added Debug

            if not found_class_in_module:
                 logger.debug(f"No suitable parser class found in module: {parser_name_key}") # <-- Added Debug

        except Exception as e:
            # Make import errors more visible
            logger.error(f"CRITICAL: Failed to import module {f.name}: {e}", exc_info=True) # <-- Changed level and added exc_info

    logger.debug(f"Finished loading from {directory}. Found {len(parsers)} parsers.") # <-- Added Debug
    return parsers

# --- (rest of the functions remain the same) ---

def load_file_parsers():
    """
    Finds and loads all valid file parser classes from the /log_parsers directory.
    """
    logger.info(f"Loading file parsers from: {PARSERS_DIR}")
    # File parsers require these attributes
    required_attrs = ['parser_name', 'parser_description', 'supported_extensions', 'can_parse', 'parse']
    return _load_parsers_from_dir(PARSERS_DIR, required_attrs)

def load_string_parsers():
    """
    Finds and loads all valid string parser classes from the /string_parsers directory.
    """
    logger.info(f"Loading string parsers from: {STRING_PARSERS_DIR}")
    # String parsers have a different contract
    required_attrs = ['parser_name', 'parser_description', 'can_parse_string', 'parse_string']
    return _load_parsers_from_dir(STRING_PARSERS_DIR, required_attrs)

# Alias for backward compatibility with engine V1
load_parsers = load_file_parsers

def create_new_parser_template(parser_name):
    """
    Generates a new file parser template in the /log_parsers directory.
    """
    try:
        from .templates import PARSER_TEMPLATE_STRING
    except ImportError:
        logger.error("Could not load PARSER_TEMPLATE_STRING from core/templates.py")
        return

    # Sanitize parser_name for filename and classname
    safe_name_part = re.sub(r'[^\w\-]+', '_', parser_name.lower()).strip('_')
    file_name = f"{safe_name_part}.py"
    class_name = "".join(word.capitalize() for word in re.split(r'[\s_-]+', parser_name))

    content = PARSER_TEMPLATE_STRING.replace("ParserTemplate", class_name)
    content = content.replace("Parser Template", parser_name.title()) # Use title case for display name

    output_path = PARSERS_DIR / file_name
    if output_path.exists():
        logger.error(f"Parser file already exists: {output_path}")
        print(f"[ERROR] Parser file already exists: {output_path}")
        return

    try:
        with open(output_path, 'w') as f:
            f.write(content)
        logger.info(f"Created new file parser template: {output_path}")
        print(f"[SUCCESS] Created new parser template at: {output_path}")
    except Exception as e:
        logger.error(f"Failed to write new parser file: {e}")
        print(f"[ERROR] Failed to write new parser file: {e}")

def create_new_string_parser_template(parser_name):
    """
    Generates a new string parser template in the /string_parsers directory.
    """
    try:
        from .templates import STRING_PARSER_TEMPLATE_STRING
    except ImportError:
        logger.error("Could not load STRING_PARSER_TEMPLATE_STRING from core/templates.py")
        print("[ERROR] String parser template not found. Please update core/templates.py")
        return

    # Sanitize parser_name for filename and classname
    safe_name_part = re.sub(r'[^\w\-]+', '_', parser_name.lower()).strip('_')
    file_name = f"{safe_name_part}.py"
    class_name = "".join(word.capitalize() for word in re.split(r'[\s_-]+', parser_name))

    content = STRING_PARSER_TEMPLATE_STRING.replace("StringParserTemplate", class_name)
    content = content.replace("String Parser Template", parser_name.title())

    output_path = STRING_PARSERS_DIR / file_name
    if output_path.exists():
        logger.error(f"Parser file already exists: {output_path}")
        print(f"[ERROR] Parser file already exists: {output_path}")
        return

    try:
        with open(output_path, 'w') as f:
            f.write(content)
        logger.info(f"Created new string parser template: {output_path}")
        print(f"[SUCCESS] Created new string parser template at: {output_path}")
    except Exception as e:
        logger.error(f"Failed to write new string parser file: {e}")
        print(f"[ERROR] Failed to write new string parser file: {e}")

