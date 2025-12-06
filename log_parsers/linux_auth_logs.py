
# Inside your new parsers/linux_auth_logs.py file

import re
import logging
from pathlib import Path
from datetime import datetime, timezone


logger = logging.getLogger(__name__)

# A set of keywords highly indicative of an auth log.
# These are often process names or key terms in the messages.
AUTH_KEYWORDS = {
    'sshd', 'sudo', 'useradd', 'polkitd', 'CRON', 'su',
    'session opened', 'new user', 'Failed password', 'Accepted password'
}

# A simple, non-capturing regex to check for the general syslog structure.
# It looks for one of the two timestamp formats, a hostname, and a process name.
SYSLOG_STRUCTURE_REGEX = re.compile(
    r'(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) \S+ \w+'
)

# Log entries
LOG_ENTRY_REGEX = re.compile(
    r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\d.:+\-]+)\s(\S+)\s([\(\)\w.-]+(?:\[\d+\])?):\s(.+)'
)

# Headers
LOG_HEADERS = [
    'timestamp', 'hostname', 'service[process_id]', 'message'
]

class LinuxAuthLogs:
    """
    This is the template class for a Parser Tongue parser.
    """

    # --- PARSER METADATA ---
    parser_name = "Linux Auth Logs"
    parser_description = "Common Linux authentication logs (e.g., /var/log/auth.log)."
    supported_extensions = ['.log', '.txt']

    def can_parse(self, filepath, file_content_sample):
        """
        Builds a confidence score based on keywords and log structure.
        """
        confidence = 0
        
        # Decode the sample for text matching, ignoring errors.
        sample_text = file_content_sample.decode('utf-8', 'ignore')

        # 1. Primary Check: Keywords (High Confidence)
        # Check if any of our highly specific keywords are in the sample text.
        for keyword in AUTH_KEYWORDS:
            if keyword in sample_text:
                # Finding a keyword gives us very high confidence.
                confidence += 85
                break # We only need to find one.

        # 2. Secondary Check: Structure (Confirms it's a syslog file)
        # Check if lines match the general syslog format.
        if SYSLOG_STRUCTURE_REGEX.search(sample_text):
            confidence += 15

        # 3. Bonus Check: Filename (Minor Confidence Boost)
        # A small bonus if the filename is conventional.
        if 'auth.log' in Path(filepath).name:
            confidence += 5
            
        # Ensure the score does not exceed 100.
        return min(100, confidence)


    def parse(self, filepath, is_batch=False):
        """
        Parses the file and returns a list of dictionaries.
        """
        parsed_data = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue 
                    
                    # 1. Create a "base" record for EVERY line
                    record = {
                        'Timestamp_UTC': None,
                        'hostname': None,
                        'service[process_id]': None,
                        'message': None,
                        'parse_status': 'UNPARSED',
                        'raw_log': line  # <--- Always add the raw log
                    }

                    # 2. Try to parse and "enrich" the record
                    match = LOG_ENTRY_REGEX.match(line)
                    if match:
                        # Zip headers and groups into a dictionary
                        parsed_fields = dict(zip(LOG_HEADERS, match.groups()))
                        
                        # Merge the parsed data into our base record
                        record.update(parsed_fields) 
                        
                        # Update status and timestamp
                        record['parse_status'] = 'SUCCESS'
                        record['Timestamp_UTC'] = self._normalize_time(record['timestamp'])
                    
                    # 3. Append the record (it's either UNPARSED or SUCCESS)
                    parsed_data.append(record)
                    # --- END NEW LOGIC ---

        except Exception as e:
            logger.error(f"Error parsing file {filepath.name}: {e}", exc_info=True)
            
        return parsed_data

    # --- HELPER METHODS ---
    def _normalize_time(self, timestamp_str):
        """
        Tries multiple common log formats to parse a timestamp string
        and converts it to a *standardized* UTC ISO-8601 string.
        """
        if not timestamp_str:
            return None

        dt = None
        
        # 1. Try to parse modern ISO 8601 formats
        try:
            dt = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            # It's not an ISO format, so we'll try the next one.
            pass

        # 2. Try to parse "classic" syslog format (if ISO failed)
        if dt is None:
            try:
                # This format has no year and no timezone.
                dt = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                
                # We must assume the current year and UTC.
                current_year = datetime.now().year
                dt = dt.replace(year=current_year, tzinfo=timezone.utc)
                
            except (ValueError, TypeError):
                # Not this format either.
                pass

        # 3. --- NEW: Standardize the output format ---
        if dt:
            try:
                # If it's "naive" (no timezone from step 2), assume it's UTC
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                
                # Convert to UTC
                dt_utc = dt.astimezone(timezone.utc)
                
                # --- THIS IS THE FIX ---
                # 1. Truncate microseconds for a clean, consistent format
                dt_no_micros = dt_utc.replace(microsecond=0)
                
                # 2. Format as ISO string and replace '+00:00' with 'Z'
                return dt_no_micros.isoformat().replace('+00:00', 'Z')
                # This will always produce 'YYYY-MM-DDTHH:MM:SSZ'
                
            except Exception as e:
                logger.warning(f"Error during timestamp standardization for '{timestamp_str}': {e}")
        
        # 4. If all parsing fails, log it and return the original string.
        logger.warning(f"Could not parse timestamp: {timestamp_str}")
        return timestamp_str
