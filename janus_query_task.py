#encoding=utf-8
import sys
import urllib2
import json
import gzip

FULLURL = 'http://cloud.appscan.io/api/analysis/v2/task/app?id=%s&q=&page=%d' #
g_headers = []

def get_header():
    headers = '''
    Connection: keep-alive
    Accept: application/json, text/plain, */*
    X-Requested-With: XMLHttpRequest
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36
    Referer: http://cloud.appscan.io/monitor-task-info.html?id=59f819420272385206e2e217
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.8,en;q=0.6
    Cookie: PGSessionId=d5bc2b09-e71c-44c0-b834-xxxxxxxx; Hm_lvt_2d9a49e839e5ceb193269aefa897ae80=1517193475,1517279958,1517826129,1517827132; Hm_lpvt_2d9a49e839e5ceb193269aefa89sfsfsfsf1517838371
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

def decode_resp(resp):
    if resp['code'] != "200":
        return 0

    page_total = resp['data']['paging']['page_total']
    page_cur = resp['data']['paging']['page']
    page_next = resp['data']['paging']['page_next']

    results = resp['data']['results']
    for data in results:
        info = [data['name'], data['appid'], data['sha1'], data['csha1'], data['create_time'], '\''+data['developer'], data['size']]
        for i in range(len(info)):
            info[i] = info[i].encode('utf-8')
        print('%s'%("\t".join(info)))

    if page_cur >= page_total:
        return 0
    return page_next

def front_query():
    headers = get_header()

    page = 1
    while(True):
        #this is slow, should considering multithread
        resp = get_response(headers, FULLURL%(sys.argv[1], page))
        page = decode_resp(resp)
        if not page:
            break

def main():
    front_query()

if __name__ == "__main__":
    '''
    http://cloud.appscan.io/monitor-task-info.html?id=59f819420272385206e2e217

    get sample info hit by task
    '''
    print("Example: %s 59f819420272385206e2e217"%sys.argv[0])
    main()
