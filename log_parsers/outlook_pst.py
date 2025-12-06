# This file provides parsing capabilities for Microsoft Outlook .pst archives.
# DEPENDENCY: This parser requires the 'libpff-python' library.
# Please install it by running: pip install libpff-python

import logging
import re
from datetime import datetime, timezone
import pypff

# Get a logger instance
logger = logging.getLogger(__name__)

# --- Re-used regex from other email parsers ---
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b')
URL_REGEX = re.compile(r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*|\bwww\.[^\s/$.?#].[^\s]*')
HTML_LINK_REGEX = re.compile(r'(?:href|src)=["\'](.*?)["\']', re.IGNORECASE)
RECEIVED_HEADER_REGEX = re.compile(r"from (.*?) by (.*?) with .*?; (.*)")
# ---

class OutlookPSTParser:
    """
    Parses a Microsoft Outlook .pst file, recursively finding all mail messages
    and extracting their data into a list of records.
    """

    # --- PARSER METADATA ---
    parser_name = "Outlook PST Archive"
    parser_description = "Extracts all emails from a .pst archive."
    supported_extensions = ['.pst']

    def can_parse(self, filepath, file_content_sample):
        # .pst files start with the magic number "!BDN"
        if file_content_sample.startswith(b'!BDN'):
            return 100
        return 0

    def parse(self, filepath, is_batch=False):
        """
        Opens a .pst file and traverses its folder structure to parse all emails.
        """
        parsed_data = []
        try:
            pst_file = pypff.file()
            pst_file.open(str(filepath))
            root_folder = pst_file.get_root_folder()
            
            # Start the recursive traversal from the root
            self._traverse_folder(root_folder, parsed_data)

        except Exception as e:
            logger.error(f"Error parsing file {filepath.name}: {e}", exc_info=True)
            
        return parsed_data

    # --- MAIN TRAVERSAL AND PARSING LOGIC ---
    def _traverse_folder(self, folder, parsed_data):
        """
        Recursively goes through folders and sub-folders to find and parse emails.
        """
        # Parse messages in the current folder
        for message in folder.sub_messages:
            try:
                # --- MODIFIED: Robust body extraction with HTML preservation ---
                body_text = None
                body_html = None
                
                # 1. Try to get the plain text body first
                plain_body_bytes = getattr(message, 'plain_text_body', None)
                if plain_body_bytes:
                    body_text = plain_body_bytes.decode('utf-8', 'ignore')

                # 2. Separately, get the HTML body if it exists
                html_body_bytes = getattr(message, 'html_body', None)
                if html_body_bytes:
                    body_html = html_body_bytes.decode('utf-8', 'ignore')
                    # If we didn't find a plain text body, create one by stripping tags
                    if not body_text:
                        body_text = re.sub(r'<[^>]+>', '', body_html)
                # --- END MODIFICATION ---

                headers = getattr(message, 'transport_headers', None)
                
                # --- MODIFIED: IOC extraction from both text and HTML ---
                # IPs are best found in the cleaned text body
                found_ips = IP_REGEX.findall(body_text or "")
                
                # URLs can be in the visible text OR hidden in HTML tags
                urls_from_text = URL_REGEX.findall(body_text or "")
                urls_from_html = HTML_LINK_REGEX.findall(body_html or "")
                
                # Combine and de-duplicate the URL lists
                found_urls = sorted(list(set(urls_from_text + urls_from_html)))
                # --- END MODIFICATION ---

                # Parse Received headers
                received_path_str = self._parse_received_path(headers)

                record = {
                    'original_date': message.delivery_time,
                    'from': getattr(message, 'sender_name', None),
                    'to': getattr(message, 'display_to', None),
                    'cc': getattr(message, 'display_cc', None),
                    'bcc': getattr(message, 'display_bcc', None),
                    'subject': getattr(message, 'subject', None),
                    'message_id': getattr(message, 'internet_message_id', None),
                    'body_text': body_text,
                    'body_html': body_html,
                    'Received_Path': received_path_str,
                    'attachment_count': message.number_of_attachments,
                    'extracted_ips': "\n".join(found_ips) if found_ips else None,
                    'extracted_urls': "\n".join(found_urls) if found_urls else None,
                }
                record['Timestamp_UTC'] = self._normalize_time(message.delivery_time)
                parsed_data.append(record)

            except Exception as e:
                logger.warning(f"Skipping a message due to parse error: {e}")

        # Recurse into sub-folders
        for sub_folder in folder.sub_folders:
            self._traverse_folder(sub_folder, parsed_data)


    # --- HELPER METHODS (re-used from other email parsers) ---
    def _normalize_time(self, timestamp_obj):
        if not timestamp_obj:
            return None
        try:
            # pypff provides datetime objects directly
            if isinstance(timestamp_obj, datetime):
                dt = timestamp_obj
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            else:
                raise TypeError(f"Unsupported timestamp type: {type(timestamp_obj)}")
        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse timestamp '{timestamp_obj}': {e}")
            return str(timestamp_obj)

    def _parse_received_path(self, raw_headers_str):
        if not raw_headers_str:
            return None
        
        header_lines = raw_headers_str.splitlines()
        received_headers = [line[9:].strip() for line in header_lines if line.lower().startswith('received:')]

        if not received_headers:
            return None

        formatted_hops = []
        for i, header in enumerate(reversed(received_headers), 1):
            clean_header = header.replace('\n', ' ').replace('\r', '')
            match = RECEIVED_HEADER_REGEX.search(clean_header)
            
            if match:
                sender, receiver, timestamp = match.groups()
                formatted_hops.append(
                    f"Hop {i}: From [{sender.strip()}] -> By [{receiver.strip()}] at [{timestamp.strip()}]"
                )
            else:
                formatted_hops.append(f"Hop {i}: [Unparsed] {clean_header}")

        return "\n".join(formatted_hops)

