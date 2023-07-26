#!/usr/bin/env python3
import binascii as ba
import socketserver
import socket

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


"""
    HMAC
"""
# 生成HMAC码
def generate_hmac(key, message):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(message)
    return hmac.finalize()

# 认证HMAC码
def verify_hmac(mac_key, message, received_hmac):
    hmac = HMAC(mac_key, hashes.SHA256())
    hmac.update(message)
    try:
        hmac.verify(received_hmac)
        return True
    except InvalidSignature:
        return False


"""
    message
"""
# message的AES加密
def encrypt_message(key, nonce, message):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return encrypted_message

# message的AES解密
def decrypt_message(key, nonce, encrypted_message):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message


"""
    file
"""
# 文件加密
def encrypt_file(key, nonce, file_path):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, 'rb') as f:
        file_data = f.read()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    return encrypted_data

# 文件解密并写入
def decrypt_file(key, nonce, encrypted_file_data, output_path):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted_file_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(decrypted_file_data)


