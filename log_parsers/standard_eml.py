# This file provides parsing capabilities for standard .eml files (RFC 822).
# It uses Python's built-in 'email' library and requires no external dependencies.

import logging
import re
from datetime import timezone
import email
import email.policy
from email.utils import parsedate_to_datetime

# Get a logger instance
logger = logging.getLogger(__name__)

# --- Pre-compiled regex for IOC extraction ---
IP_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b')
URL_REGEX = re.compile(r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*|\bwww\.[^\s/$.?#].[^\s]*')

# --- Regex for parsing a single 'Received:' header ---
# This is a simplified regex to grab the most important parts.
RECEIVED_HEADER_REGEX = re.compile(r"from (.*?) by (.*?) with .*? for .*?; (.*)")

class StandardEML:
    """
    Parses standard .eml files, extracting headers, body, and attachment info.
    """

    # --- PARSER METADATA ---
    parser_name = "Standard EML File"
    parser_description = "Parses standard .eml files (RFC 822), extracting headers, body, and attachment info."
    supported_extensions = ['.eml']

    def can_parse(self, filepath, file_content_sample):
        """
        Detects an .eml file by looking for common email headers.
        """
        # Decode for regex text matching, ignoring errors
        sample_text = file_content_sample.decode('utf-8', 'ignore')
        
        # Look for the presence of standard email headers like From, To, Subject, Date
        if re.search(r'^(From|To|Date|Subject):', sample_text, re.MULTILINE):
            return 90  # High confidence
        return 0

    def can_parse(self, filepath, file_content_sample):
        # A simple check for common EML headers
        if b'Received:' in file_content_sample and b'From:' in file_content_sample:
            return 90
        return 0

    def parse(self, filepath, is_batch=False):
        parsed_data = []
        try:
            with open(filepath, 'rb') as f:
                # Use the BytesParser to handle various encodings gracefully
                msg = BytesParser(policy=policy.default).parse(f)

            # --- Robust body extraction with HTML preservation ---
            body_text = None
            body_html = None

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition'))

                    if "attachment" not in content_disposition:
                        if content_type == "text/plain" and not body_text:
                            body_text = part.get_payload(decode=True).decode('utf-8', 'ignore')
                        elif content_type == "text/html" and not body_html:
                            body_html = part.get_payload(decode=True).decode('utf-8', 'ignore')
            else:
                # Not a multipart message, just get the payload
                if msg.get_content_type() == "text/plain":
                    body_text = msg.get_payload(decode=True).decode('utf-8', 'ignore')
                elif msg.get_content_type() == "text/html":
                    body_html = msg.get_payload(decode=True).decode('utf-8', 'ignore')

            # If we only got an HTML body, create a text version by stripping tags
            if body_html and not body_text:
                body_text = re.sub(r'<[^>]+>', '', body_html)

            # --- IOC extraction from both text and HTML ---
            found_ips = IP_REGEX.findall(body_text or "")
            urls_from_text = URL_REGEX.findall(body_text or "")
            urls_from_html = HTML_LINK_REGEX.findall(body_html or "")
            found_urls = sorted(list(set(urls_from_text + urls_from_html)))

            # Parse Received headers
            received_path_str = self._parse_received_path(msg)
            
            # Extract attachment names
            attachments = [part.get_filename() for part in msg.walk() if part.get_filename()]

            record = {
                'original_date': msg['Date'],
                'from': msg['From'],
                'to': msg['To'],
                'cc': msg['Cc'],
                'bcc': msg['Bcc'],
                'subject': msg['Subject'],
                'message_id': msg.get('Message-ID'),
                'body_text': body_text,
                'body_html': body_html,
                'Received_Path': received_path_str,
                'attachment_count': len(attachments),
                'attachment_names': ', '.join(attachments) if attachments else None,
                'extracted_ips': "\n".join(found_ips) if found_ips else None,
                'extracted_urls': "\n".join(found_urls) if found_urls else None,
            }
            record['Timestamp_UTC'] = self._normalize_time(msg['Date'])
            parsed_data.append(record)

        except Exception as e:
            logger.error(f"Error parsing file {filepath.name}: {e}", exc_info=True)
            
        return parsed_data

    # --- HELPER METHODS ---
    def _normalize_time(self, timestamp_str):
        if not timestamp_str:
            return None
        try:
            # email.utils.parsedate_to_datetime is great for RFC 822 dates
            dt = email.utils.parsedate_to_datetime(timestamp_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except (ValueError, TypeError):
            logger.warning(f"Could not parse timestamp: {timestamp_str}")
            return timestamp_str

    def _parse_received_path(self, msg_obj):
        received_headers = msg_obj.get_all('Received', [])
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