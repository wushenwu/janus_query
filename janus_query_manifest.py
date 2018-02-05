#coding=utf-8
import sys
import argparse

from task_util import *
from task_mgr import *

from filter_domain import FilterDomain
obj_filter_domain = FilterDomain()

try:
    reload(sys)
    sys.setdefaultencoding('utf-8')
except:
    pass

API_TYPES = ["files", "receiver", "activity", "service","strings", "cert", "permission",]# "provider"]
API_TYPES = ["strings"]
API_TYPES = ["files"]

def process_permission(resp, type, sha1, extra, queue):
    #print(resp)
    pass

def process_cert(resp, type, sha1, extra, queue):
    #print('\t'.join([sha1, type, resp['data']['items']['subjectName']]))
    pass

g_is_interest = []
def process_strings(resp, type, sha1, extra, queue):
    for item in resp['data']['datas']:
        try:
            data = '\t'.join(type, sha1, item['value'])
            rule = 'strings:"%s"'%item['value']
            queue.put({'data':data, 'rule':rule, 'extra':extra})
        except:
            pass

    #interest is returned for every page, but we only need once
    global g_is_interest
    if sha1 in g_is_interest:
        return

    g_is_interest.append(sha1)
    for item in resp['data']['interest']:
        for value in item['items']:
            if obj_filter_domain.isExclude(value):
                continue
            data = '\t'.join([sha1, item['name'], value])
            rule = '%s:"%s"'%(item['name'], value)
            queue.put({'data':data, 'rule':rule, 'extra':extra})

def process_files(resp, type, sha1, extra, queue):
    '''
    {
        "err_msg": "",
        "code": "200",
        "data": {
            "paging": {
                "row_total": 14,
                ....
            },
            "datas": [
                {
                "innermd5": "9bfd36a891141f03ad66a1a81f21d557",
                "innersha1": "54515cbbf4c36abb0755109b0fdbe081b0b40ec4",
                "file": "assets/ic.png",
                "size": 52783
                },
    '''
    for doc in resp['data']['datas']:
        #if 'kt' in doc['file'] or 'kotlin' in doc['file']:
        data = '\t'.join([sha1, type, doc['innersha1'], doc['file']])
        rule = 'innersha1:"%s"\t%s'%(doc['innersha1'], doc['file'])

        queue.put({'data':data, 'rule':rule, 'extra':extra})

    #later, we need to query for this value, to get to know how many samples can be filtered by this way
    #generate query
    #innersha1:"54515cbbf4c36abb0755109b0fdbe081b0b40ec4"

def process_items(resp, type, sha1, extra, queue):
    for item in resp['data']['items']:
        if not item:
            continue
        data = '\t'.join([sha1, type, item])
        rule = '%s:"%s"'%(type, item)

        queue.put({'data': data, 'rule': rule, 'extra':extra })

def decode_resp(resp, extra):
    type, sha1 = extra['type'], extra['sha1']
    try:
        if not resp or resp['code'] != "200":
            return

        if resp['data']['len'] == 0:
            return
    except:
        pass

    queue = extra['queue']
    extra.pop('queue')

    try:
        g_decode_funcPtr[type](resp, type, sha1, extra, queue)
    except:
        process_items(resp, type, sha1, extra, queue)

g_decode_funcPtr = {
        'files' : process_files,
        'strings' : process_strings,
        'pemission' : process_permission,
        'cert' : process_cert,
}

def consumer(queue, fname):
    fw = open(fname, 'ab')
    fw_rule = open(fname + '_rule.txt', 'ab')

    d_query_status = {}
    while True:
        doc = queue.get(True)
        fw.write('%s\n'%(doc['data']))
        fw_rule.write('%s\n'%(doc['rule']))
        queue.task_done()

        cache.doCache(doc['extra'])


def print_usage():
    usage = '''
    python %s 04092efc88d29f7a7b67027d0b8dde58f81e8afb    # directly query by sha1
    python %s file_containing_sha1.txt                     # lines of sha1 within the file
    '''%(__file__, __file__)
    #print(usage)
    return(usage)

def get_query():
    parser = argparse.ArgumentParser(description='query for the manifest', usage = print_usage())
    parser.add_argument('value', help='file path or the sha1 to be queried')

    args = parser.parse_args()
    l_query = []
    try:
        with open(args.value) as fr:
            l_query = fr.read().splitlines()
    except:
        l_query.append(args.value)

    return l_query

def process():
    cookie = 'Cookie: PGSessionId=d5bc2b09-e71c-44c0-b834-4esfsfsfsfdsdsf; Hm_lvt_2d9a49e839e5ceb193269aefa897ae80=1517193475,1517279958,1517826129,1517827132; Hm_lpvt_2d9a49e839e5ceb193269aefa89ssfsjfsfjs'

    FULLURL = "http://cloud.appscan.io/api/app/%s?sha1=%s"

    obj = TaskUtil(cookie, decode_resp)

    taskMgr = TaskMgr(callback=consumer, fname = 'dump_manifest.txt', nprocess = 1)

    just_total = False
    for line in get_query():
        items = line.strip().replace('"', '').split("\t")
        sha1 = items[0]
        if len(sha1) != 40:
            continue

        for type in API_TYPES:
            url = FULLURL%(type, sha1)
            cur_query = '%s_%s'%(sha1, type)
            extra     = {'queue':taskMgr.queue, 'cur_query':cur_query, 'url':url, 'just_total': just_total, 'page':1, 'type': type, 'sha1':sha1 }
            obj.add_task(url, extra, taskMgr.pool)

    taskMgr.run()

def main():
    process()

if __name__ == '__main__':
    main()
