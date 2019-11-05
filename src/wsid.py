import json
import logging
from datetime import datetime

import nacl.signing 
import nacl.public 
import nacl.encoding 
import nacl.hash

class WSID:
    def __init__(self, keybody, identity, ttl=10, logger=None):

        hexencoder=nacl.encoding.HexEncoder

        self.signing_key=nacl.signing.SigningKey(keybody,hexencoder)
        self.encryption_key=nacl.public.PrivateKey(keybody, hexencoder)

        self.manifest = {
            "sig":   self.signing_key.verify_key.encode(hexencoder).decode(),
            "enc":   self.encryption_key.public_key.encode(hexencoder).decode()
        }

        self.identity = identity
        self.ttl      = ttl
        self.logger   = logger or logging.getLogger('wsid')
        #sigbytes=self.signing_key.verify_key.encode(hexencoder) 
        #app.logger.info("HASH blake2b: %s" % nacl.hash.blake2b( sigbytes, digest_size=4 ) )
   
    def sign(self, message):
        
        message = message.decode() if isinstance(message,bytes) else message

        b64=nacl.encoding.Base64Encoder
        hexenc=nacl.encoding.HexEncoder

        now=int(datetime.utcnow().timestamp())
        claims = {
            'iss': self.identity,
            'iat': now,
            'exp': now + self.ttl
        }
        claims_b64 = b64.encode(json.dumps(claims).encode()).decode()
         
        payload=message + "." + claims_b64

        self.logger.debug("PAYLOAD: %s" % payload)
            
        signed = self.signing_key.sign(payload.encode())
        sigstring = hexenc.encode( signed.signature ).decode()
        
        return payload+"."+sigstring
