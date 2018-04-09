#!/usr/bin/env python3

import json
import time
import random
import string
import logging

from des_wrapper import encrypt, decrypt

from flask import jsonify, request
from flask import Flask

template = "%(asctime)s [%(levelname)s] KDS server --- %(message)s"
logging.basicConfig(level='INFO', format=template)

app = Flask(__name__)


def read_db():
    with open('as.json') as f:
        db = json.load(f)

    return db


def get_random_str(size=8, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))


@app.route('/as', methods=['POST', 'GET'])
def as_server():
    body = json.loads(request.data)
    db = read_db()

    user_id = body.get('id')
    user_key = db['users'].get(user_id)
    client_tgs_key = get_random_str(size=8)

    tgt = encrypt({
        'user_id': user_id,
        'tgs': db['tgs'],
        't1': int(time.time()),
        'p1': db['p1'],
        'client_tgs_key': client_tgs_key,
    }, db['as_tgs_key'])

    result = encrypt({
        'tgt': tgt,
        'client_tgs_key': client_tgs_key
    }, user_key)

    return jsonify({'result': result}), 200


@app.route('/tgs', methods=['POST', 'GET'])
def tgs_server():
    body = json.loads(request.data)
    db = read_db()

    tgt, auth1, ss_id = body['tgt'], body['auth1'], body['ss_id']

    tgt_decrypted = decrypt(tgt, db['as_tgs_key'])
    auth1_decrypted = decrypt(auth1, tgt_decrypted['client_tgs_key'])

    if tgt_decrypted['user_id'] != auth1_decrypted['user_id']:
        logging.warning('Check user_id failed')

        return jsonify({'result': ''}), 200

    if tgt_decrypted['t1'] + tgt_decrypted['p1'] < auth1_decrypted['t2']:
        logging.warning('User %s use old tgt', tgt_decrypted['user_id'])

        return jsonify({'result': ''}), 200

    client_ss_key = get_random_str(size=8)

    tgs = encrypt({
        'user_id': tgt_decrypted['user_id'],
        'ss_id': ss_id,
        't3': int(time.time()),
        'p2': db['p2'],
        'client_ss_key': client_ss_key,
    }, db['tgs_ss_key'])

    result = encrypt({
        "tgs": tgs,
        "client_ss_key": client_ss_key
    }, tgt_decrypted['client_tgs_key'])

    return jsonify({'result': result}), 200


@app.route('/ss', methods=['POST', 'GET'])
def ss_server():
    body = json.loads(request.data)
    db = read_db()

    tgs, auth2 = body['tgs'], body['auth2']

    tgs_decrypted = decrypt(tgs, db['tgs_ss_key'])
    auth2_decrypted = decrypt(auth2, tgs_decrypted['client_ss_key'])

    if tgs_decrypted['user_id'] != auth2_decrypted['user_id']:
        logging.warning('SS server: check user_id failed')

    result = encrypt({
        "t4": auth2_decrypted["t4"] + 1
    }, tgs_decrypted['client_ss_key'])

    return jsonify({'result': result}), 200
