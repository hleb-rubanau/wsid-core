from .helpers import assert_bytes, default_request_to_payload_extractor
import urllib.request

class WSIDClient():
    """ implements API for identity server's clients"""
    def __init__(self, url):
        self.url=url
        self.signurl=url+"/sign"

    def sign(self, msg, **kwargs):
        assert_bytes(msg)
        return urllib.request.urlopen( self.signurl , data=msg ).read()
                  
    def sign_request(self, request, payload_extractor=None, **kwargs):
        if not payload_extractor:
            payload_extractor=default_request_to_payload_extractor

        payload=payload_extractor(request)

        _, claims, signature = self.sign(payload).split(b".")
        
        # for signed requests we omit 'payload', 
        # which should be instead recalculated on receiving side 
        return b"WSID "+claims+b"."+signature
