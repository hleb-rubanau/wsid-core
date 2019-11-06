from cachetools import cached, LRUCache, TTLCache
import urllib.request
import json
from datetime import datetime
import logging
from base64 import b64encode
from .exceptions import *

import nacl.signing
import nacl.encoding

def new_private_key():
    return nacl.signing.SigningKey.generate().encode( 
                                               encoder=nacl.encoding.HexEncoder
                                             ).decode()

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


def assert_bytes(msg):
    if not isinstance(msg,bytes):
        raise TypeError("Byte-like object needed")            
    
def default_request_to_payload_extractor(request):
    fields = [ 
                request.method.encode(), 
                base64.b64encode(request.url),
             ]

    return b":".join(fields)
