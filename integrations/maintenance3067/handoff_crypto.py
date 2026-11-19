"""Dedicated authenticated envelopes for registration -> maintenance handoff."""
import base64,json,secrets,time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(key, payload, direction):
    nonce=secrets.token_bytes(12)
    raw=json.dumps(payload,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
    encrypted=AESGCM(key).encrypt(nonce,raw,('loomy-handoff/v1/'+direction).encode())
    return {'v':1,'nonce':base64.b64encode(nonce).decode(),'body':base64.b64encode(encrypted).decode()}


def open_envelope(key, envelope, direction):
    if not isinstance(envelope,dict) or envelope.get('v')!=1:raise ValueError('invalid_envelope')
    nonce=base64.b64decode(envelope['nonce'],validate=True)
    body=base64.b64decode(envelope['body'],validate=True)
    if len(nonce)!=12 or not 16<=len(body)<=16000:raise ValueError('invalid_envelope')
    value=json.loads(AESGCM(key).decrypt(nonce,body,('loomy-handoff/v1/'+direction).encode()))
    if not isinstance(value,dict) or abs(time.time()-value.get('ts',0))>120:raise ValueError('expired_envelope')
    if not isinstance(value.get('requestId'),str) or len(value['requestId'])!=32:raise ValueError('invalid_request')
    return value

