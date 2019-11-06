import json
import logging

import nacl.encoding
from .exceptions import *
from .helpers import validate_timestamps, fetch_identity, validate_identity_url, default_request_to_payload_extractor

def validate(msg, logger=None):
  
    logger=logger or logging.getLogger('wsid.validate')
        
    payload, claimsdata, signaturehex = msg.split(b'.')
    
    b64     =   nacl.encoding.Base64Encoder
    hexenc  =   nacl.encoding.HexEncoder
    claims  =   json.loads(b64.decode(claimsdata))

    validate_timestamps(claims['iat'],claims['exp'])

    identity = claims['iss']
    
    validate_identity_url(identity)
    signer_key_body = fetch_identity( identity )['sig']
    logger.debug("VERIFICATION KEY=%s" % [ signer_key_body ] )
    
    verifier = nacl.signing.VerifyKey(signer_key_body, nacl.encoding.HexEncoder)
  
    logger.debug("VERIFIER reencoded: %s" % verifier.encode( nacl.encoding.HexEncoder ).decode() ) 
 
    # it's important to take claimsdata, not reserialized claims, as result may formally differ 
    signed_payload  =   payload+b"."+claimsdata
    
    signature = hexenc.decode( signaturehex )

    logger.debug("CHECKING PAYLOAD %s against signature %s" % (signed_payload, signature))
    try:
        if verifier.verify(signed_payload, signature):
            return (identity, payload, claims)
    except nacl.exceptions.BadSignatureError:
        raise InvalidSignature


def validate_request(request, logger=None, payload_extractor=None):
    logger=logger or logging.getLogger('wsid.validate_request') 
    payload_extractor = payload_extractor or default_request_to_payload_extractor

    signature=request.headers['Authorization']
    if signature.startswith("WSID "):
        signature=signature[len("WSID "):]

    payload = payload_extractor( request )
   
    full_payload =  payload + b'.' + signature.encode()
    return validate(full_payload, logger)
    
    
