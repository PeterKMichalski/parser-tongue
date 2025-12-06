# parsers/mssql_audit_parser.py

import re
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# --- Regex Definitions ---
# Regex to find key details in the message field
CLIENT_IP_REGEX = re.compile(r'\[CLIENT:\s*([\d.]+)\]')
USER_REGEX = re.compile(r"user '([^']+)'")
ERROR_REGEX = re.compile(r'Error:\s*(\d+)')
SEVERITY_REGEX = re.compile(r'Severity:\s*(\d+)')
STATE_REGEX = re.compile(r'State:\s*(\d+)')

# --- Expected Header Structure (based on sample) ---
# Note: Real logs might vary based on server configuration.
# This parser assumes 4 main comma-separated fields initially.
EXPECTED_FIELDS = ['Timestamp', 'Category', 'Subcategory', 'Message']


class MSSQLAuditParser:
    """
    Parses text-based Microsoft SQL Server Audit Logs.
    Assumes a comma-separated format similar to common file audit configurations.
    May not work correctly for SQL Trace (.trc) or Extended Events (.xel) files.
    """

    # --- PARSER METADATA ---
    parser_name = "MS SQL Server Audit Log"
    parser_description = "Parses text-based SQL Server Audit logs (often .log files)."
    supported_extensions = ['.log', '.txt'] # Add others if needed, e.g., '.trc' if exported

    def can_parse(self, filepath, file_content_sample):
        """
        Builds a confidence score based on keywords and log structure.
        """
        confidence = 0
        sample_text = file_content_sample.decode('utf-8', 'ignore')

        # Check for SQL Server timestamp format (MM/DD/YYYY HH:MM:SS)
        if re.search(r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}', sample_text):
            confidence += 40

        # Check for characteristic keywords
        if "Logon," in sample_text or "Login failed" in sample_text:
            confidence += 30
        if "Error:" in sample_text and "Severity:" in sample_text:
            confidence += 30

        # Check for client IP pattern
        if CLIENT_IP_REGEX.search(sample_text):
            confidence += 15

        return min(100, confidence)

    def parse(self, filepath, is_batch=False):
        """
        Parses the file line by line, splitting by comma and
        extracting details from the message field.
        """
        parsed_data = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    # --- Base Record ---
                    record = {
                        'Timestamp_UTC': None,
                        'Category': None,
                        'Subcategory': None,
                        'Message': None,
                        'Client_IP': None,
                        'User': None,
                        'Error_Code': None,
                        'Severity': None,
                        'State': None,
                        'parse_status': 'UNPARSED',
                        'raw_log': line
                    }

                    # --- Attempt to Parse ---
                    try:
                        # Split by comma, expecting roughly 4 fields
                        parts = line.split(',', 3) # Split only 3 times max

                        if len(parts) >= 4:
                            record['Category'] = parts[1].strip()
                            record['Subcategory'] = parts[2].strip()
                            record['Message'] = parts[3].strip()

                            # Normalize Timestamp
                            record['Timestamp_UTC'] = self._normalize_time(parts[0].strip())

                            # Extract details from Message
                            ip_match = CLIENT_IP_REGEX.search(record['Message'])
                            if ip_match: record['Client_IP'] = ip_match.group(1)

                            user_match = USER_REGEX.search(record['Message'])
                            if user_match: record['User'] = user_match.group(1)

                            error_match = ERROR_REGEX.search(record['Message'])
                            if error_match: record['Error_Code'] = error_match.group(1)

                            sev_match = SEVERITY_REGEX.search(record['Message'])
                            if sev_match: record['Severity'] = sev_match.group(1)

                            state_match = STATE_REGEX.search(record['Message'])
                            if state_match: record['State'] = state_match.group(1)

                            record['parse_status'] = 'SUCCESS'

                        else:
                            # Line didn't split as expected
                            logger.warning(f"Line {line_num+1} in {filepath.name} has unexpected format: {line}")
                            record['Message'] = line # Store whole line as message if split fails

                    except Exception as parse_ex:
                        logger.warning(f"Error parsing line {line_num+1} in {filepath.name}: {parse_ex} | Line: {line}")
                        record['parse_status'] = 'PARSE_ERROR'
                        record['Message'] = line # Store original line in message on error

                    parsed_data.append(record)

        except Exception as e:
            logger.error(f"Error reading or processing file {filepath.name}: {e}", exc_info=True)

        return parsed_data

    # --- HELPER METHODS ---
    def _normalize_time(self, timestamp_str):
        """
        Converts MM/DD/YYYY HH:MM:SS format to UTC ISO-8601 string.
        Assumes the original log time is in the local timezone of the server
        or UTC if conversion fails (common ambiguity).
        """
        if not timestamp_str:
            return None

        dt = None
        try:
            # Try parsing the specific format
            dt = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')

            # SQL Server logs *usually* don't include timezone.
            # We have to make an assumption. Assuming UTC is the safest bet
            # for correlation, though it might be server's local time.
            dt_utc = dt.replace(tzinfo=timezone.utc)

            # --- Standardize the output format ---
            dt_no_micros = dt_utc.replace(microsecond=0)
            return dt_no_micros.isoformat().replace('+00:00', 'Z')

        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse timestamp '{timestamp_str}': {e}")
            return timestamp_str # Return original on failure
