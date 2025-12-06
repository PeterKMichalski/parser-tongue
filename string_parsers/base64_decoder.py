# string_parsers/base64_decoder.py
import base64
import logging

logger = logging.getLogger(__name__)

class Base64Decoder:
    parser_name = "Base64 Decoder"
    parser_description = "Decodes a Base64-encoded string."

    def can_parse_string(self, input_string):
        # A simple check: is the length a multiple of 4?
        if len(input_string) % 4 == 0:
            return 80 # Reasonably confident
        return 0

    def parse_string(self, input_string):
        try:
            decoded_bytes = base64.b64decode(input_string)
            # Try to decode as UTF-8, but fall back to raw bytes
            try:
                decoded_string = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                decoded_string = str(decoded_bytes)

            return {
                'original': input_string,
                'decoded': decoded_string,
                'parse_status': 'SUCCESS'
            }
        except Exception as e:
            logger.error(f"Base64 decode error: {e}")
            return {
                'original': input_string,
                'decoded': None,
                'parse_status': 'ERROR'
            }