#coding=utf-8
import sys
import argparse
import json
import time

from task_util import *
from task_mgr import *
import cache

try:
    reload(sys)
    sys.setdefaultencoding('utf-8')
except:
    pass

def decode_resp(resp, extra):
    if not resp or resp['code'] != "200":
        return

    queue = extra['queue']
    extra.pop('queue')  # to avoid 'Unserializable message'

    if extra['just_total']:
        queue.put({'data': resp['data']['paging'] , 'extra':extra})
        return

    datas = resp['data']['datas']
    for data in datas:
        #info =[data['sha1'], data['csha1'], data['appid'], data['name'], data['download_time'], data['developer'], data['md5'], data['size'], data['version']]
        queue.put({'data':data, 'extra':extra})

def consumer(queue, fname):
    fw = open(fname, 'ab')

    d_query_status = {}
    while True:
        doc = queue.get(True)
        fw.write('%s\n'%json.dumps(doc['data']))
        queue.task_done()

        cache.doCache(doc['extra'])


def print_usage():
    usage = '''
    python %s 04092efc88d29f7a7b67027d0b8dde58f81e8afb    # directly query the keyword, without indicating the type
    python %s com.example.helloworldMobile.SmsReceiver    # directly query the keyword, without indicating the type
    python %s 'receiver:"com.example.helloworldMobile.SmsReceiver"'  # query the specified key:value
    python %s t.txt
    '''%(__file__, __file__, __file__, __file__)
    return(usage)

def get_query():
    parser = argparse.ArgumentParser(description='query like the front page', usage = print_usage())
    parser.add_argument('value', help='file path or the query like innersha1:"xxxx"')
    parser.add_argument('-t', '--total', action='store_true', help='just get the page_total and raw_total')

    args = parser.parse_args()
    l_query = []
    try:
        with open(args.value) as fr:
            l_query = fr.read().splitlines()
    except:
        l_query.append(args.value)

    return (l_query, args.total)

def process():
    #DO REMEMBER to update your cookie here
    cookie = 'Cookie: Hm_lvt_2d9a49e839e5ceb193269aefa897ae80=1516233831,1517054214,1517193475,1517279958; LANG=cn; PGSessionId=d5bc2b09-e71c-44c0-b834-yyyyyyyy; Hm_lpvt_2d9a49e839e5ceb193269aefa897ae80=xxxxx'

    #
    FULLURL = "http://cloud.appscan.io/api/search?type=app&q=%s"

    #
    obj = TaskUtil(cookie, decode_resp)

    #
    taskMgr = TaskMgr(callback=consumer, fname = 'dump_daily_20180205.txt')

    lines, just_total = get_query()
    #lines, just_total = ['malware_20180201'], False
    for line in lines:
	cur_query = quote(line.strip())
        url       = FULLURL%(cur_query)
        #url       = 'http://cloud.appscan.io/api/search?type=app&q=&office=%E4%BB%BF%E5%86%92' #仿冒
        #url       = 'http://cloud.appscan.io/api/search?type=app&q=&maltype=%E6%81%B6%E6%84%8F' #恶意
        extra     = {'queue':taskMgr.queue, 'cur_query':cur_query, 'url':url, 'just_total': just_total, 'page':1 }
	obj.add_task(url, extra, taskMgr.pool)

    taskMgr.run()


def main():
    process()

if __name__ == '__main__':
    main()
