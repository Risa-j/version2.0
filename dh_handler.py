import os
import socketserver
import sys
import binascii as ba

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


# 导入DH参数(Risa_5037文件夹中的'dh_2048_params')
import utils


def load_dh_params():
    with open('./dh_2048_params.bin', 'rb') as f:   # 'rb':以二进制只读方式读取文件
        params = load_der_parameters(f.read(), default_backend())   # 以二进制方式读入文件，并转为DH参数
    print("Paramters have been loaded successfully!")
    print("Server is ready for requests ...")
    return params   # 返回读入的DH参数


# 根据DH参数，随机生成DH私钥(private key)和公钥(public key)
def generate_dh_key(params):
    return params.generate_private_key()    # 注意，虽然这里名字是private_key，但实际上会同时返回private key & public key

# 验证来自客户端(client)的公钥(public key)是否是一个合法的DH实例
def check_client_public_key(public_key):
    if isinstance(public_key, dh.DHPublicKey):
        return True
    else:
        return False

# 自定义重载DH Server的Request Handler类
class Dh_Handler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):    # 创建这个类的对象时，需要传入参数request, client_address, server
        # 在Base Request Handler基础上做自定义修改
        self.params = load_dh_params()  # 导入DH参数
        self.state = 0  # 当前状态：即收到但尚未处理的请求(request)数量

        # 加载最基础的由socketserver提供的Request Handler类
        socketserver.BaseRequestHandler.__init__(self, request=request, client_address=client_address, server=server)


    # 处理请求(request)并给予回应(response)
    def handle(self):
        """
            协商negotiation
        """
        # <<-- 接收客户端的请求 <<--
        self.data = self.request.recv(3072).strip()     # 这里限制了单条消息的长度上限为 3072 Bytes
        # 检验是否收到合法字段 "Client request to establish connection."
        if self.state == 0 and self.data == b'Client request to establish connection.':  # TODO: 这里可以改成别的，但要和risasclient中保持一致
            # 更新state
            self.state = 1
            # 打印信息
            print("The message received from the client is:", self.data)    # 打印接收到的信息
            print("Current state: ", self.state)    # 打印服务器当前状态
            # -->> 回复客户端 -->>
            response = b'The server agrees to establish a connection.'   # TODO: 回复，也可以改成别的
            self.request.sendall(response)     # 将response返回给客户端
        else:
            # -->> 针对非法确认字段的回复 -->>
            response = b'Invalid Request!'
            self.request.sendall(response)
            return      # 非法字段，直接返回，不继续处理来自客户端的其它消息

        """ 
            交换DH参数 
        """
        # <<-- 接收客户端的请求 <<--
        self.data = self.request.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
        # 检验是否收到合法字段 "Please provide me with DH parameters."
        if self.state == 1 and self.data == b'Please provide me with DH parameters.':    # TODO: 这里可以改成别的，但要和risasclient中保持一致
            # 更新state
            self.state = 2
            # 打印信息
            print("The message received from the client is:", self.data)  # 打印接收到的信息
            print("Current state: ", self.state)  # 打印服务器当前状态
            # -->> 回复DH参数 -->>
            response = self.params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            self.request.sendall(response)
        else:
            # -->> 针对非法确认字段的回复 -->>
            response = b'Invalid Request!'
            self.request.sendall(response)
            return      # 非法字段，直接返回，不继续处理来自客户端的其它消息

        """ 
            交换密钥
        """
        # <<-- 接收客户端的请求 <<--
        self.data = self.request.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
        # 获取客户端公钥 "Client public key:"
        if self.state == 2 and bytearray(self.data)[0:18] == b'Client public key:':
            # 更新state
            self.state = 3
            # 提取公钥
            client_public_key = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())
            # 提取公钥成功的话
            if client_public_key:
                # 根据DH参数，随机生成服务器自己的公钥和私钥
                server_key = generate_dh_key(self.params)
                # -->> 将服务器公钥传回给客户端 -->>
                response = b'Server public key:' + server_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.request.sendall(response)
                # 基于客户端提供的公钥，计算共享密钥(shared secret)
                self.shared_secret = server_key.exchange(client_public_key)
                # 打印信息
                print("The message received from the client is:", self.data)  # 打印接收到的信息
                print("Current state: ", self.state)  # 打印服务器当前状态
                print("Shared secret:{}".format(ba.hexlify(self.shared_secret)))    # 打印共享密钥
            else:
                # -->> 针对非法确认字段的回复 -->>
                response = b'Invalid Request!'
                self.request.sendall(response)
                return  # 非法字段，直接返回，不继续处理来自客户端的其它消息

        """ 
            密钥派生，向服务器提供nonce 
        """
        # <<-- 接收客户端的请求 <<--
        self.data = self.request.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
        if self.state == 3 and bytearray(self.data) == b'Please provide the nonce.':
            # 更新state
            self.state = 4
            # 设置HKDF密钥派生方法
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=48,
                salt=None,  # TODO: 我看paper里写了要使用salt，或许需要改一下
                info=b'Handshake data',
                backend=default_backend()
            )
            # 从共享密钥中进行密钥派生
            key_material = hkdf.derive(self.shared_secret)
            self.key = key_material[:16]  # 前16bit为key
            self.mac_key = key_material[16:32]  # 后16bit为mac key
            # 生成随机数nonce(number once)
            self.nonce = os.urandom(16)
            # -->> 向客户端返回nonce -->>
            self.request.sendall(b'Server nonce:' + self.nonce)
        else:
            # -->> 针对非法确认字段的回复 -->>
            response = b'Invalid Request!'
            self.request.sendall(response)
            return  # 非法字段，直接返回，不继续处理来自客户端的其它消息

        """ 
            客户端成功收到nonce，进入功能选择 
        """
        # <<-- 接收客户端的请求 <<--
        self.data = self.request.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
        if self.state == 4 and bytearray(self.data) == b'Nonce received!':
            # 更新state
            self.state = 5
            # -->> 请客户端选择功能 -->>
            response = b'Please choose: [1] Send text message, [2] Send File.'
            self.request.sendall(response)

        """ 
            根据用户的选择，提供服务 
        """
        # <<-- 接收客户端的请求 <<--
        self.data = self.request.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
        if self.state == 5 and bytearray(self.data) == b'1':
            # 更新state
            self.state = 6  # 进入文字传输模式
            print("Message mode.")
            # -->> 告知客户端可以发送文字消息 -->>
            response = b'Now you can send text message!'
            self.request.sendall(response)
        elif self.state == 5 and bytearray(self.data) == b'2':
            # 更新state
            self.state = 7  # 进入文件传输模式
            print("File mode.")
            # -->> 告知客户端可以发送文件 -->>
            response = b'Now you can send a file!'
            self.request.sendall(response)
        else:
            # -->> 告知用户非法输入 -->>
            response = b'Invalid input, please choose again!'
            self.request.sendall(response)
            # state回退
            self.state = 4

        """
            响应文字传输功能
        """
        if self.state == 6:
            while True:
                # <<-- 接收客户端发送的message <<--
                self.data = self.request.recv(3072).strip()  # 这里限制了单条消息的长度上限为 3072 Bytes
                received_message = self.data[:-32]      # 前32个字符是客户端加密后的message
                received_hmac = self.data[-32:]         # 后32个字符是客户端传过来的hmac
                # 身份验证
                if utils.verify_hmac(self.mac_key, received_message, received_hmac):        # FIXME: 这里身份验证不通过
                    # 解密
                    decrypted_message = utils.decrypt_message(self.key, self.nonce, received_message)
                    # 打印解密后的信息
                    print("Message from client:{}".format(decrypted_message.decode()))
                    # -->> 服务器回复message -->>
                    response = input("Please input your response:")
                    if response == 'exit':  # TODO: 退出命令exit
                        break
                    # 将response加密
                    encrypted_message = utils.encrypt_message(self.key, self.nonce, response.encode())
                    # 获取hmac码
                    hmac = utils.generate_hmac(self.mac_key, encrypted_message)
                    self.request.sendall(encrypted_message + hmac)
                    print("Send response successfully!")
                else:
                    print("Message authentication failed!")

        """
            响应文件传输功能
        """
        if self.state == 7:
            # <<-- 接收客户端发送的file data <<--
            file_data = self.request.recv(3072).strip()
            received_file = file_data[:-32]     # 前32个字符是客户端加密后的file
            received_hmac = file_data[-32:]     # 后32个字符是客户端传过来的hmac
            # 身份验证
            if utils.verify_hmac(self.mac_key, received_file, received_hmac):
                # 解密
                utils.decrypt_file(self.key, self.nonce, received_file, output_path='received.txt')
                # 打印
                print("File received successfully! Data received has already been saved in 'received.txt'.")
                # -->> 回复客户端已收到 -->>
                response = b'File received successfully!'
                self.request.sendall(response)
            else:
                print('File authentication failed!')


