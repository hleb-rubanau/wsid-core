import os
import logging
from base64 import b64encode
from datetime import datetime

from flask import Flask, request
from wsid import WSID

LOG_LEVEL = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper())
app = Flask(__name__)
app.logger.setLevel(LOG_LEVEL)
#app.logger.addHandler(logging.StreamHandler())

def is_like_b64(msg):
    return msg.replace('=','').isalnum()


wsid=WSID(  os.getenv("WSID_PRIVATE_KEY"), 
            os.getenv("WSID_IDENTITY"), 
            logger=app.logger
            )


def get_public_keys():
    return wsid.manifest

def do_sign():
    payload = request.get_data()
    if not payload.replace('=','').alnum():
        payload = b64encode(payload)
    return wsid.sign( payload ) 

app.add_url_rule('/', 'index', get_public_keys )
app.add_url_rule('/manifest','manifest', get_public_keys )
app.add_url_rule('/sign','sign', do_sign, methods=["POST"] )

