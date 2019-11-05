from .helpers import assert_bytes, default_request_to_payload_extractor
import requests

class WSIDClient():
    def __init__(self, url):
        self.url=url

    def sign(self, msg, **kwargs):
        assert_bytes(msg)
        return requests.post(self.url+'/sign', data=data, kwargs)
                  
    def sign_request(self, request, payload_extractor=None, **kwargs):
        if not payload_extractor:
            payload_extractor=default_request_to_payload_extractor

        payload=payload_extractor(request)

        _, claims, signature = self.sign(payload)
        
        return b"WSID "+claims+b"."signature
