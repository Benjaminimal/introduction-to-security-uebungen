#!/usr/bin/env python3

import json
import hashlib
import binascii
from time import time
from os import urandom
from functools import wraps
from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, abort, flash, redirect, render_template, request, url_for
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from resources import *


app = Flask(__name__)


class CryptoError(Exception):
    pass


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        cookie = request.cookies.get('session')
        if cookie is None:
            abort(404)
        try:
            session = get_cookie_value(cookie)
            if time() - session['timestamp'] > (60 * 5):
                return bad_request('Session expired')
            return f(user=session['user'], *args, **kwargs)
        except CryptoError:
            return bad_request('Decryption failed')
        except Exception as e:
            import traceback
            print(traceback.print_exc())
            return bad_request('Malformed session')
    return decorated_function


def bad_request(message):
    return render_template('error.html', message=message), 400


def secure_hash(password, salt):
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, 31337)
    return binascii.hexlify(dk)


def secure_encrypt(data):
    try:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        iv = urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()
    except Exception:
        raise CryptoError


def secure_decrypt(data):
    try:
        iv, data = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(padded_data)
        return unpadded_data + unpadder.finalize()
    except Exception:
        raise CryptoError


def set_cookie_value(data):
    return urlsafe_b64encode(secure_encrypt(json.dumps(data).encode()))


def get_cookie_value(data):
    return json.loads(secure_decrypt(urlsafe_b64decode(data.encode())))


@app.route('/uyulala')
@login_required
def uyulala(user):
    return render_template('uyulala.html', user=user, flag=flag)


@app.route('/login', methods=['POST'])
def login():
    try:
        salt, dk = users[request.form['user']].split(b':')
        if secure_hash(request.form['password'].encode(), salt) == dk:
            session = {'timestamp': time()}
            session.update(request.form)
            response = app.make_response(redirect(url_for('uyulala')))
            response.set_cookie('session', value=set_cookie_value(session))
            return response
        else:
            return bad_request('Invalid password')
    except KeyError:
        return bad_request('Invalid username')


@app.route('/')
def home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0')
