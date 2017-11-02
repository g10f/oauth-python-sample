import base64
import json
import logging

logger = logging.getLogger(__name__)


def _urlsafe_b64encode(raw_bytes):
    s = base64.urlsafe_b64encode(raw_bytes)
    return s.rstrip(b'=')


def _urlsafe_b64decode(b64string):
    # Guard against unicode strings, which base64 can't handle.
    b64string = b64string.encode('ascii')
    padded = b64string + b'=' * (4 - len(b64string) % 4)
    return base64.urlsafe_b64decode(padded)


def _json_encode(data):
    return json.dumps(data, separators=(',', ':'))
