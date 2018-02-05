#coding=utf-8
import sys
import json
import os
import time
import multiprocessing
from multiprocessing import Pool

import cache

try:
    #python3
    from urllib import request
    from urllib.request import urlretrieve
    from urllib.parse import quote
except:
    #python2
    import urllib2
    import urllib
    from urllib import quote
    from urllib import urlretrieve

    reload(sys)
    sys.setdefaultencoding('utf8')

g_headers = []  #python 2
g_header_d = {} #python3

def proxy_do_task(cls, url, extra):
    '''
    this is used to solve multiprocessing pool problems
    http://maoxiaomeng.com/2015/12/11/python%E7%9A%84mutliprocessing%E5%BC%95%E8%B5%B7%E7%9A%84%E5%B0%8F%E9%97%AE%E9%A2%98/
    '''
    cls._do_task(url, extra)

class TaskUtil:
    def __init__(self, cookies, decode_resp):
        '''
        cookies should like 'Cookie: PGSessionId=fa6a0546-9c03-4f34-acbf-f6282198020f; Hm_lvt_2d9a4'

        decode_resp is the callback function to deal with repsonses
        '''
        self.headers, self.headers_d = self.get_header(cookies)
        self.decode_resp = decode_resp
        self.l_task_info = []
        self.response = {}  #cached response for each url

    def fetch_page(self, url, extra):
        resp = self.get_response(url)
        page = self.decode_resp(resp, extra)

    def get_page_total(self, url):
        resp = self.get_response(url)
        page_total = self._get_page_total(resp)
        return page_total

    def get_raw_total(self, url):
        resp = self.get_response(url)
        try:
            return resp['data']['paging']['row_total']
        except:
            return -1

    def _do_task(self, url, extra):
        print(url)
        resp = self.get_response(url)
        self.decode_resp(resp, extra)

    def add_task(self, url, extra, pool):
        page_total = self.get_page_total(url)

        if extra['just_total']:
            pool.apply_async(proxy_do_task, args=(self, url, extra))
            return

        for page in range(1, page_total + 1):
            tmp_url = '%s&page=%d'%(url, page)
            tmp_extra = dict(extra)
            tmp_extra['url'] = tmp_url
            tmp_extra['page'] = page

            if cache.isCached(tmp_extra):
                print('skip %s %d'%(tmp_extra['cur_query'], tmp_extra['page']))
                continue

            pool.apply_async(proxy_do_task, args=(self, tmp_url, tmp_extra))

    def get_header(self, cookies):
        headers = '''
Proxy-Connection: keep-alive
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Referer: http://cloud.appscan.io/search-app.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,en;q=0.6
'''
        headers = '''
Connection: keep-alive
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36
Referer: http://nc.janus.wa/search-app.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
    '''

        headers = '%s\n%s'%(headers.rstrip(), cookies)
        l_headers = []
        d_headers = {}
        for line in headers.split("\n"):
            if not line.strip():
                continue

            items = line.strip().split(":", 1)
            l_headers.append((items[0], items[1]))
            d_headers[items[0]] = items[1]
        return(l_headers, d_headers)

    def get_response(self, url):
        try:
            return self.response[url]
        except:
            pass

        doc = ''
        try:
            #python3
            req = request.Request(url, headers=self.headers_d)
            doc = request.urlopen(req).read()
        except:
            #python2
            opener = urllib2.build_opener()
            opener.addheaders = self.headers
            doc = opener.open(url).read()

        try:
            content = json.loads(doc)
        except:
            content = ''

        self.response[url] = content
        return content

    def _get_page_total(self, resp):
        try:
            if not resp or resp['code'] != "200":
                return 0
        except:
            pass

        try:
            return(resp['data']['paging']['page_total'])
        except:
            return 1
