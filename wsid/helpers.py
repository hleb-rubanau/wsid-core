from cachetools import cached, LRUCache, TTLCache
import urllib.request
import json
from datetime import datetime
import logging
from base64 import b64encode
from .exceptions import *

def validate_identity_url(url):
    if not(url.startswith('https://') or url.startswith('http://127.0.0')):
        raise InsecureIdentityURL(url)

def validate_timestamps(issued_at, expires_at):
    now=int( datetime.utcnow().timestamp() )
    if (issued_at > now) or  (expires_at < now):
        raise InvalidTimestamps

@cached(cache=TTLCache(maxsize=128, ttl=600))
def fetch_identity(url):
    with urllib.request.urlopen(url) as response:
        data=response.read()
    return json.loads(data)

def request_to_payload(request, extra_processor=None):
    fields = [ 
                request.method, 
                base64.b64encode(request.url),
             ]

    if extra_processor:
        extra_part = extra_processor(request)

        if extra_part:
            if not isinstance(extra_part,bytes):
                extra_part=extra_part.encode()

    if extra_part:
        fields += [ extra_part ]

    return b":".join(extra_part)
