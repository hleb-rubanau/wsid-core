import requests
from requests import Request
from requests.api import request
from .client import WSIDClient

class SignedRequests:
    def __init__(self, url):
        self.wcidclient=WSIDClient(url)

    def process(self, method, url, *args, **kwargs):
        plain_kwargs=dict(**kwargs)
        payload_extractor = plain_kwargs.pop('payload_extractor', None)
        r=Request(method, url, *args, **plain_kwargs)
        signature = self.wcidclient.sign_request(r, payload_extractor)
                
        if not plain_kwargs.get('headers'):
            plain_kwargs['headers']={}

        plain_kwargs['headers']['Authorization']=signature
        return request(method, url, **plain_kwargs)
    
     
