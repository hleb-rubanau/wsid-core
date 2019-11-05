from cachetools import cached, LRUCache, TTLCache
import urllib.request
import json
from datetime import datetime

class InsecureIdentityURL(Exception):
    pass

class InvalidTimestamps(Exception): 
    pass

def validate_identity_url(url):
    if not(url.startswith('https://') or url.startswith('http://127.0.0'))
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

