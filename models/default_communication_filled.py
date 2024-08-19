"""
    添加默认请求/响应时的数据
"""
from datetime import datetime

default_req_dict = {
    "默认GET": "GET /index.html?index=1 HTTP/1.1\r\nHost: 192.168.57.160\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n\r\n",
    "默认POST": "POST /index.html HTTP/1.1\r\nHost: 192.168.48.147\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 30\r\n\r\nusername=admin&password=123456",
}

default_rsp_dict = {
    "默认响应（200）": f"HTTP/1.1 200 OK\r\nCache-Control: private\r\nContent-Type: text/html; charset=utf-8\r\nServer: nginx\r\nDate: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhidden"
}
