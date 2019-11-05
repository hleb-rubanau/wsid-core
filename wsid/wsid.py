import json
import logging
from datetime import datetime

import nacl.signing 
import nacl.public 
import nacl.encoding 
import nacl.hash

from .helpers import *

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

        self.logger.debug("PAYLOAD: %s" % payload)
            
        signed = self.signing_key.sign(payload)
        sigstring = hexenc.encode( signed.signature )
        
        return payload+b"."+sigstring



def validate(msg):
  
    payload, claimsdata, signature = msg.split(b'.')
    
    b64     =   nacl.encoding.Base64Encoder
    claims  =   json.loads(b64.decode(claimsdata))

    validate_timestamps(claims['iat'],claims['exp'])

    identity = claims['iss']
    
    validate_identity_url(identity)
    signer_key_body = fetch_identity( identity )['sig']
    
    verifier = nacl.signing.VerifyKey(signer_key_body, nacl.encoding.HexEncoder)
   
    # it's important to take claimsdata, not reserialized claims, as result may formally differ 
    signed_payload  =   payload+b"."+claimsdata

    if verifier.verify(signed_payload, signature):
        return (identity, payload, claims)
