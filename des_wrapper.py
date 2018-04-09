#!/usr/bin/env python3

import json
import pyDes
import binascii


def encrypt(value, key):
    des = pyDes.des(key)
    data = json.dumps(value)

    encrypt_data = des.encrypt(data, padmode=pyDes.PAD_PKCS5)
    result = binascii.hexlify(encrypt_data).decode('utf-8')

    return result


def decrypt(data, key):
    des = pyDes.des(key)

    bytes_data = binascii.unhexlify(data.encode('utf8'))
    result = des.decrypt(bytes_data, padmode=pyDes.PAD_PKCS5).decode('utf-8')

    value = json.loads(result)

    return value
