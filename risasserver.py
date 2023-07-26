import socketserver
import sys

# 导入DH参数(Risa_5037文件夹中的'dh_2048_params')
from dh_handler import Dh_Handler


# main function
def main():
    host = ''   # 设置为"监听任何ip地址(listen on any address)"
    port = 8888     # 监听8888端口
    # 创建TCP Server的实例，并设置它使用我们自定义的host(ip地址)，port(端口)和Request Handler
    dh_server = socketserver.TCPServer((host, port), Dh_Handler)    # TODO: 这里的Dh_Handler在dh_handler.py里
    try:
        dh_server.serve_forever()   # 一旦程序开始运行，server就持续提供服务
    except KeyboardInterrupt:   # 异常：如果程序被人为终止
        dh_server.shutdown()    # 服务器停止工作
        sys.exit(0)     # server停止工作，正常退出，返回0


if __name__ == '__main__':
    main()


