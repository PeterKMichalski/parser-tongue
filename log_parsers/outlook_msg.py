# This file provides parsing capabilities for Microsoft Outlook .msg files.
# DEPENDENCY: This parser requires the 'extract_msg' library.
# Please install it by running: pip install extract-msg

import logging
from datetime import datetime, timezone
import extract_msg
import re


# Get a logger instance
logger = logging.getLogger(__name__)

# --- Pre-compiled regex for IOC extraction ---
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b')
URL_REGEX = re.compile(r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*|\bwww\.[^\s/$.?#].[^\s]*')
HTML_LINK_REGEX = re.compile(r'(?:href|src)=["\'](.*?)["\']', re.IGNORECASE)


# --- Regex for parsing a single 'Received:' header ---
# This is a simplified regex to grab the most important parts.
RECEIVED_HEADER_REGEX = re.compile(r"from (.*?) by (.*?) with .*?; (.*)")

class OutlookMSG:
    """
    Parses Microsoft Outlook .msg files, extracting headers, body,
    and attachment information.
    """

    # --- PARSER METADATA ---
    parser_name = "Outlook MSG File"
    parser_description = "Parses Microsoft Outlook .msg files, extracting headers, body, and attachment info."
    supported_extensions = ['.msg']

    def can_parse(self, filepath, file_content_sample):
        # .msg files start with the OLE magic number
        if file_content_sample.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
            return 100
        return 0

    def parse(self, filepath, is_batch=False):
        parsed_data = []
        try:
            msg = extract_msg.Message(str(filepath))

            # --- Robust body extraction with HTML preservation ---
            body_text = getattr(msg, 'body', None)
            body_html = getattr(msg, 'html', None)
            
            # If we only got an HTML body, create a text version by stripping tags
            if body_html and not body_text:
                body_text = re.sub(r'<[^>]+>', '', body_html)
            # ---

            # --- IOC extraction from both text and HTML ---
            found_ips = IP_REGEX.findall(body_text or "")
            urls_from_text = URL_REGEX.findall(body_text or "")
            urls_from_html = HTML_LINK_REGEX.findall(body_html or "")
            
            # Combine and de-duplicate the URL lists
            found_urls = sorted(list(set(urls_from_text + urls_from_html)))
            # ---
            
            # Parse Received headers
            received_path_str = self._parse_received_path(msg)
            
            attachment_list = [att.long_filename for att in msg.attachments]

            record = {
                'original_date': msg.date,
                'from': msg.sender,
                'to': msg.to,
                'cc': msg.cc,
                'bcc': msg.bcc,
                'subject': msg.subject,
                'message_id': msg.messageId,
                'body_text': body_text,
                'body_html': body_html,
                'Received_Path': received_path_str,
                'attachment_count': len(attachment_list),
                'attachment_names': ', '.join(attachment_list) if attachment_list else None,
                'extracted_ips': "\n".join(found_ips) if found_ips else None,
                'extracted_urls': "\n".join(found_urls) if found_urls else None,
            }
            record['Timestamp_UTC'] = self._normalize_time(msg.date)
            parsed_data.append(record)

        except Exception as e:
            logger.error(f"Error parsing file {filepath.name}: {e}", exc_info=True)
            
        return parsed_data

    # --- HELPER METHODS ---
    def _normalize_time(self, timestamp_obj):
        if not timestamp_obj:
            return None
        try:
            if isinstance(timestamp_obj, datetime):
                dt = timestamp_obj
            elif isinstance(timestamp_obj, str):
                dt = datetime.strptime(timestamp_obj, '%Y-%m-%d %H:%M:%S%z')
            else:
                raise TypeError(f"Unsupported timestamp type: {type(timestamp_obj)}")

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError) as e:
            logger.warning(f"Could not parse timestamp '{timestamp_obj}': {e}")
            return str(timestamp_obj)

    def _parse_received_path(self, msg_obj):
        try:
            # The 'header' property contains the full raw headers as a string
            raw_headers_str = msg_obj.header
            if not raw_headers_str:
                return None
        except (AttributeError, KeyError):
            return None
            
        header_lines = str(raw_headers_str).splitlines()
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