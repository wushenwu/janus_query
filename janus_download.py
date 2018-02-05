#encoding=utf-8
import sys
import urllib2
import urllib
import json
import os
from multiprocessing.dummy import Pool as ThreadPool

FULLURL = "http://cloud.appscan.io/api/cloud/download?sha1="
g_headers = []

def get_header():
    headers = '''
Connection: keep-alive
Accept: application/json, text/plain, */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36
Referer: http://cloud.appscan.io/app-report.html?id=16e5c9fea5d7a5287a9e41a4d566a95be795500b
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: Hm_lvt_2d9a49e839e5ceb193269aefa897aesfsljfls6,1514858385,1515467115,1515716865; PGSessionId=29ace456-e0ad-4521-bd17-sdfsf5d0a46; Hm_lpvt_2d9a49e839e5ceb897aefsfsfsff70498
    '''
    l_headers = []
    for line in headers.split("\n"):
        if not line.strip():
            continue

        items = line.strip().split(":", 1)
        l_headers.append((items[0], items[1]))
    return(l_headers)

def get_response(headers, fullurl):
    opener = urllib2.build_opener()
    opener.addheaders = headers
    fd = opener.open(fullurl)
    content = json.load(fd)
    return content

def decode_resp(resp, sha1):
    if resp['code'] != "200":
        return

    url = resp['data']
    filename = sha1 + '.apk'
    if os.path.isfile(filename):
        return

    urllib.urlretrieve(url, filename)

def get_resp(sha1):
    url = '%s%s'%(FULLURL, sha1)
    resp = get_response(g_headers, url)
    page = decode_resp(resp, sha1)

def front_query_multithread():
    global g_headers
    g_headers = get_header()

    #
    s_sha1 = set([sys.argv[1]])
    '''
    with open(sys.argv[1]) as fr:
        for line in fr:
            s_sha1.add(line.strip().split("\t")[0].strip().replace('"', ''))
    '''

    pool = ThreadPool(1)
    results = pool.map(get_resp, s_sha1)

    # close the pool and wait for the work to finish
    pool.close()
    pool.join()

def main():
    front_query_multithread()

if __name__ == "__main__":
    main()
