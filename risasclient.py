#!/usr/bin/env python3
import binascii as ba
import socketserver
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

import utils

def main():
    host = 'localhost'  # 主机地址使用本地环回地址 127.0.0.1
    port = 8888     # 端口与服务器监听端口保持一致 8888

    # 创建tcp socket实例
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 使用自定义的主机地址和端口建立连接
    sock.connect((host, port))

    """ 
        协商negotiation) 
    """
    # -->> 向服务器发送请求 -->>
    request = b'Client request to establish connection.'    # TODO: 这里可以改成别的，但要和risasserver中保持一致
    sock.sendall(request)

    """ 
        检验服务器返回的消息，并择机交换DH参数
    """
    # <<-- 接收服务器的回复 <<--
    received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
    # 打印信息
    print("Received:{}".format(received))
    if received == b'The server agrees to establish a connection.':
        # -->> 向服务器发送请求 -->>
        request = b'Please provide me with DH parameters.'  # TODO: 这里可以改成别的，但要和risasserver中保持一致
        sock.sendall(request)
    else:
        # 若服务器返回了bad response
        print('Bad response!')
        # 关闭socket连接
        sock.close()
        return  # 直接退出客户端程序，不继续向服务器发起请求

    """ 
        检验DH参数，并交换密钥 
    """
    # <<-- 接收服务器的回复 <<--
    received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
    # 打印信息
    print('Received:{}'.format(received))
    # 获取DH参数
    dh_params = load_pem_parameters(received, default_backend())
    # 检验从服务器获取的参数是否为合法的DH参数
    if isinstance(dh_params, dh.DHParameters):
        # 如果是，则生成客户端自己的公钥和私钥
        client_key = dh_params.generate_private_key()
        # -->> 向服务器发送自己的公钥 -->>
        request = b'Client public key:' + client_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        sock.sendall(request)
    else:
        # 若服务器返回了bad response
        print('Bad response!')
        # 关闭socket连接
        sock.close()
        return  # 直接退出客户端程序，不继续向服务器发起请求

    """ 
        接收服务器的key，计算共享密钥(shared secret) 
    """
    # <<-- 接收服务器的回复 <<--
    received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
    # 打印信息
    print('Received:{}'.format(received))
    # 获取服务器公钥
    if bytearray(received)[0:18] == b'Server public key:':
        # 提取公钥
        server_public_key = load_pem_public_key(bytes(bytearray(received)[18:]), default_backend())
        # 如果提取的公钥是一个有效的DH公钥
        if isinstance(server_public_key, dh.DHPublicKey):
            # 计算共享密钥
            global shared_secret    # 声明为全局变量
            shared_secret = client_key.exchange(server_public_key)
            # 打印共享密钥
            print('Shared Secret:{}'.format(ba.hexlify(shared_secret)))
    else:
        # 若服务器返回了bad response
        print('Bad response!')
        # 关闭socket连接
        sock.close()
        return  # 直接退出客户端程序，不继续向服务器发起请求

    """ 
        密钥派生，请求服务器提供nonce 
    """
    # 设置HKDF密钥派生方法
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=None,  # TODO: 我看paper里写了要使用salt，或许需要改一下
        info=b'Handshake data',
        backend=default_backend()
    )
    # 从共享密钥中进行密钥派生
    key_material = hkdf.derive(shared_secret)
    key = key_material[:16]     # 前16bit为key
    mac_key = key_material[16:32]   # 后16bit为mac key

    # -->> 请求服务器提供nonce(number once) -->>
    request = b'Please provide the nonce.'
    sock.sendall(request)

    """ 
        接收到服务器提供的nonce，并向服务器发送确认
    """
    # <<-- 接收服务器的回复 <<--
    received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
    # 打印信息
    print('Received:{}'.format(received))
    # 确定nonce的开始位置
    nonce_start = received.find(b'Server nonce:') + len('Server nonce:')
    # 提取nonce
    nonce = received[nonce_start:].strip()
    # -->> 告知服务器已收到nonce -->>
    request = b'Nonce received!'
    sock.sendall(request)

    """ 
        功能选择 
    """
    # <<-- 接收服务器的回复 <<--
    received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
    # 打印信息
    print('Received:{}'.format(received))
    # -->> 告知服务器用户的选择 -->>
    # 用户选择功能
    request = input("Please input '1' or '2' to choose:")
    request = request.encode()
    sock.sendall(request)

    """
        开始文字传输or文件传输
    """
    # <<-- 接收服务器的回复 <<--
    received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
    # 打印信息
    print('Received:{}'.format(received))
    # 如果是文字传输
    if bytearray(received) == b'Now you can send text message!':
        while True:
            # 请用户输入文字信息
            message = input('Please input the message:')
            if message == 'exit':   # TODO: 退出命令 'exit'
                break
            # 信息加密
            encrypted_message = utils.encrypt_message(key, nonce, message.encode())
            # 生成HMAC码(基于hash的消息认证码)
            hmac = utils.generate_hmac(mac_key, encrypted_message)
            # -->> 向服务器发送message -->>
            sock.sendall(encrypted_message + hmac)  # 加密后的msg和hmac码
            print("Message send successfully!")
            # <<-- 接收服务器对message的回复 <<--
            response = sock.recv(3072).strip()
            received_message = response[:-32]   # 服务器的加密回复
            received_hmac = response[-32:]      # 服务器传来的hmac
            # 身份验证
            if utils.verify_hmac(mac_key, received_message, received_hmac):
                # 解密
                decrypted_message = utils.decrypt_message(key, nonce, received_message)
                print('Response from server:{}'.format(decrypted_message.decode()))
            else:
                print('Message authentication failed!')
    # 如果是文件传输
    elif bytearray(received) == b'Now you can send a file!':
        while True:
            # 输入文件名
            file_name = input('Please input filename:')
            # 获取加密后的文件信息
            encrypted_file_data = utils.encrypt_file(key, nonce, file_name)
            # 生成hmac
            hmac = utils.generate_hmac(mac_key, encrypted_file_data)
            # -->> 发送文件 -->>
            sock.sendall(encrypted_file_data + hmac)
            # <<-- 接收服务器的回复 <<--
            received = sock.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
            # 打印
            print('Received from server:{}'.format(received))
    else:
        print('Invalid input!')

if __name__ == '__main__':
    main()





















