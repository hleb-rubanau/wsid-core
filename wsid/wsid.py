import json
from datetime import datetime

import nacl.signing 
import nacl.public 
import nacl.encoding 
import nacl.hash

from .helpers import *

class WSID:
    def __init__(self, keybody, identity, ttl=10, logger=None):
        
        self.logger   = logger or logging.getLogger('wsid')

        hexencoder=nacl.encoding.HexEncoder

        self.signing_key=nacl.signing.SigningKey(keybody,hexencoder)
        self.encryption_key=nacl.public.PrivateKey(keybody, hexencoder)

        self.manifest = {
            "sig":   self.signing_key.verify_key.encode(hexencoder).decode(),
            "enc":   self.encryption_key.public_key.encode(hexencoder).decode()
        }

        self.logger.debug("SIGKEY as string: %s" % self.manifest['sig'])

        self.identity = identity
        self.ttl      = ttl
        #sigbytes=self.signing_key.verify_key.encode(hexencoder) 
        #app.logger.info("HASH blake2b: %s" % nacl.hash.blake2b( sigbytes, digest_size=4 ) )
   
    def sign(self, message):
        """message: a bytes-like object"""
        
        b64=nacl.encoding.Base64Encoder
        hexenc=nacl.encoding.HexEncoder

        now=int(datetime.utcnow().timestamp())
        claims = {
            'iss': self.identity,
            'iat': now,
            'exp': now + self.ttl
        }
        claims_b64 = b64.encode(json.dumps(claims).encode())
         
        payload=message + b"." + claims_b64

        self.logger.debug("PAYLOAD TO SIGN: %s" % payload)
        signed = self.signing_key.sign(payload)
        self.logger.debug("GENERATED SIGNATURE: %s" % signed.signature)
        sigstring = hexenc.encode( signed.signature )
        self.logger.debug("GENERATED SIGNATURE HEX: %s" % sigstring)
        
        return payload+b"."+sigstring



