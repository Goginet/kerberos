#!/usr/bin/env python3

import time
import json

from contextlib import closing
from http.client import HTTPConnection
from des_wrapper import encrypt, decrypt


def client_auth_request(user_id, user_key):
    data = {'id': user_id}

    resp = request('/as', data)
    resp_decrypted = decrypt(resp, user_key)

    return resp_decrypted['tgt'], resp_decrypted['client_tgs_key']


def client_tgs_request(user_id, tgt, ss_id, client_tgs_key):
    t2 = int(time.time())

    auth = {'user_id': user_id, 't2': t2}
    auth_encrypted = encrypt(auth, client_tgs_key)

    data = {'tgt': tgt, 'auth1': auth_encrypted, 'ss_id': ss_id}
    resp = request('/tgs', data)

    resp_decrypted = decrypt(resp, client_tgs_key)

    return resp_decrypted['tgs'], resp_decrypted['client_ss_key']


def client_ss_request(user_id, client_ss_key, tgs):
    t4 = int(time.time())

    auth = {'user_id': user_id, 't4': t4}
    auth_encrypted = encrypt(auth, client_ss_key)

    data = {'tgs': tgs, 'auth2': auth_encrypted}
    resp = request('/ss', data)

    resp_decrypted = decrypt(resp, client_ss_key)

    if resp_decrypted['t4'] == t4 + 1:
        return client_ss_key

    return None


def main():
    user_id = 'test'
    user_key = '12345678'
    ss_id = 1

    tgt, client_tgs_key = client_auth_request(user_id, user_key)

    tgs, client_ss_key = client_tgs_request(user_id, tgt, ss_id, client_tgs_key)

    if client_ss_request(user_id, client_ss_key, tgs) is not None:
        print('Ok, key = {}', client_ss_key)


def request(url, body, host='localhost', port=5000):
    with closing(HTTPConnection(host, port, timeout=1000)) as conn:
        conn.request('POST', url, body=json.dumps(body))
        resp = conn.getresponse()
        data = resp.read()
        code = resp.code

    return json.loads(data.decode())['result']


if __name__ == '__main__':
    main()
