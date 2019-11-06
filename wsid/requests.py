import requests
import logging
from requests import Request
from requests.api import request
from .client import WSIDClient

class SignedRequests:
    def __init__(self, url):
        self.wsidclient=WSIDClient(url)

    def process(self, method, url, *args, **kwargs):
        plain_kwargs=dict(**kwargs)

        payload_extractor = plain_kwargs.pop('payload_extractor', None)
        logger = plain_kwargs.pop('logger',None) or logging.getLoggeer('wsid.SignedRequests') 

        r=Request(method, url, *args, **plain_kwargs)
        signature = self.wsidclient.sign_request(r, payload_extractor)

        if not plain_kwargs.get('headers'):
            plain_kwargs['headers']={}

        plain_kwargs['headers']['Authorization']=signature
        
        logger.debug("Signed request kwargs are=%s" % plain_kwargs)
        return request(method, url, **plain_kwargs)
    
     
