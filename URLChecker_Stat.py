#-*- coding: UTF-8 -*-
import sys
import re
import urllib
import subprocess
import random
import string
import operator
from collections import defaultdict
from URLChecker import *
from URLChecker_Util import *

SUSPICIOUS_TYPE_DOMAIN_HOSTS = "domain_hosts"
SUSPICIOUS_TYPE_DOMAIN_URLS = "domain_urls"
SUSPICIOUS_TYPE_URL_KEYWORDS = "url_keyword"
SUSPICIOUS_TYPE_DOMAIN_NEW = "domain_new"

rand_str = string.lowercase + string.digits
def generateRandomString(length):
    return ''.join(random.choice(rand_str) for i in xrange(length))

def dumpInfoCnt(filename, d_key_value, extrainfo = ''):
    fw = open(filename, 'w')

    sorted_key_value = sorted(d_key_value.items(), key=lambda item: len(item[1]), reverse=True)
    for item in sorted_key_value:
        key = item[0]
        value = item[1]

        fw.write("%s\t_cnt_\t%d"%(key, len(value)))
        if extrainfo:
            fw.write("\t%s"%(extrainfo))
        fw.write("\n")
        for v in value:
            fw.write("\t%s\n"%v)
    fw.close()

def loadDomainKeyWords():
    '''
    this is usually the all_host_ip data,  the newly domain
    mkiller_2016-12-29%26domain.txt

    date	host_ip
    2016-12-29	titan-rich.com
    2016-12-29	yunniupin.com
    '''
    s_domain = set()
    try:
        sys.argv[2]
    except:
        return set()

    with open(sys.argv[2]) as fr:
        for line in fr:
            s_domain.add(line.strip().split("\t")[1])
    return s_domain

def loadHostKeywords():
    return set(["mail.easternmills.com","xy.jx.dynamic.163data.com.cn.jxzhjy.com",])

def finditem(anchor_begin, anchor_end, line):
    index = line.find(anchor_begin)
    if -1 == index:
        return ''

    if anchor_end == '':
        return line[index + len(anchor_begin) : ]

    index_end = line[index + len(anchor_begin): ].find(anchor_end)
    if -1 == index_end:
        return line[index + len(anchor_begin) :]
    return line[index + len(anchor_begin) : index + len(anchor_begin) + index_end]

class URLChecker_Stat:
    def __init__(self):
        self.urlchecker = URLChecker()
        self.url_util = URLChecker_Util()

        self.d_domain_hosts = {}
        self.d_hostInAlexaTop_urls = {}

        self.new_domain = set()
        self.domain_level = {}

        self.s_suspiciousDomain = defaultdict(set)  #'domain':'suspicious_type'   suspicious_type can be domain_hosts, or domain_url
        self.d_sus_domain_keyword = {}  # to know domain suspicious by which keyword

        self.s_DomainKeywords = loadDomainKeyWords()
        #self.s_HostKeywords = loadHostKeywords()

        self.d_urlkeywords_cnt = defaultdict(int)
        self.d_urlkeywords_domain = defaultdict(set)
        self.d_urlkeywords_isInAlexTop = defaultdict(set)

    def hitKeyWords(self, line):
        for k in self.s_keywords:
            if line.find(k) != -1:
                return True
        return False

    def hitDomain(self, domain):
        if domain in self.s_DomainKeywords:
            return True
        return False

    def loadNewHostIP(self):
        '''
        新增hosts 对应的domain数据
        '''
        try:
            with open('new_domain.txt') as fr:
                for line in fr:
                    self.new_domain.add(line.strip())
        except:
            pass

    def loadDomainLevel(self):
        '''
        goplaygames.es	1	1.000000	1	1
        '''
        try:
            with open('domain_level.txt') as fr:
                for line in fr:
                    domain, cntHosts, riskpercent, total, risk = line.strip().split("\t")
                    self.domain_level[domain] = '\t'.join([total, riskpercent])
        except:
            pass

    def extractUrlKeywords(self, url, domain, isInAlexaTop):
        #d_urlkeywords_cnt

        domain = '_'.join([domain, str(isInAlexaTop)])

        host, sep, path = url.partition('/')
        items = re.split('[?=&/_-]', path)
        for item in items:
            if item.isdigit():
                continue

            if item.replace('.apk', '').isdigit():
                continue

            self.d_urlkeywords_cnt[item] += 1
            self.d_urlkeywords_domain[item].add(domain)
            self.d_urlkeywords_isInAlexTop[item].add(isInAlexaTop)

    def dumpUrlKeywords(self):
        fw = open('dump_urlkeywords_cnt.txt', 'wb')
        l_hdr = ['keyword', 'cnt', 'length', 'isInAlexaTop', 'hasNonBlackDomain', 'cntDomain', 'domains\n']
        fw.write('\t'.join(l_hdr))

        sorted_key_value = sorted(self.d_urlkeywords_cnt.items(), key=lambda item: item[1], reverse=True)
        for item in sorted_key_value:
            key = item[0]
            if not key.strip():
                continue

            if len(key) < 4:
                continue

            isInAlexaTop = False
            if True in self.d_urlkeywords_isInAlexTop[key]:
                isInAlexaTop = True

            hasNonBlackDomain = False
            for domain in self.d_urlkeywords_domain[key]:
                domain = domain.replace('_True', '').replace('_False', '')
                if domain not in self.s_suspiciousDomain:
                    hasNonBlackDomain = True
                    break

            infoAry = [key, str(item[1]), str(len(key)), str(isInAlexaTop), str(hasNonBlackDomain), str(len(self.d_urlkeywords_domain[key])), ' '.join(self.d_urlkeywords_domain[key])]
            fw.write('%s\n'%('\t'.join(infoAry)))
        fw.close()

    def checkHasCNAME(self, domain):
        hostInfo = self.d_domain_hosts[domain]
        host = list(hostInfo['hosts'])[0]

        try:
            cmd = 'ping -n 1 %s'%host
            output = subprocess.check_output(cmd, shell=True)
        except:
            return True

        #ping dz.zpjishi.com
        #正在 Ping dz.zpjishi.com.w.kunlunea.com [124.238.232.229] 具有 32 字节的数据:
        ping_host = finditem('Ping ', '[', output)
        print 'pinged host: ', ping_host
        if not ping_host:
            return True

        if len(ping_host.strip()) != len(host):
            return True

        return False

    def judgeSuspicious_ByKeyWords(self, filename):
        '''
        根据总结的keyword pattern, 判定domain
        '''
        self.doStat_Domain_Hosts(filename)

        suspicious_type = "urlkeywords"

        #关键词的获取应该自动化产生
        s_suspicious_urlkeywords = set()
        for domain, hostInfo in self.d_domain_hosts.iteritems():
            if hostInfo['isInAlexaTop'] or hostInfo['isip'] or not hostInfo['isvaliddomain']:
                continue

            for url in hostInfo['urls']:
                for keyword in s_suspicious_urlkeywords:
                    #remove those can be false
                    if keyword.replace('.apk', '').isdigit():
                        continue
                    if url.find(keyword) != -1:
                        #if self.checkHasCNAME(domain):
                        if True:
                            self.s_suspiciousDomain[domain].add(SUSPICIOUS_TYPE_URL_KEYWORDS)
                            #需要对keyword进行记录、验证
                            self.d_sus_domain_keyword[domain] = keyword
                            break

    def judgeSuspicious_ByDomainHosts(self, filename):
        '''
        根据domain下hosts的分布，来判定domain恶意性：
        1） 应做到与样本级别无关
        2） 甚至应该做到与url无关， 仅是domain与Hosts的特征角度

        考虑以下几点：
        1）cnt_hosts 要达到一定值： 代表着在观察期内，同一个domain下，hosts处于多变的情况
        2) subhost_parts: 为1， 形如1482498504849.tahrdq.cn
        3) sub_max_len: 也就是


        E:\DailySample\JiJiuXiang\20161224\mkiller_all_host_ip\
        '''
        self.doStat_Domain_Hosts(filename)

        suspicious_type = "domain_hosts"

        for domain, hostInfo in self.d_domain_hosts.iteritems():
            if hostInfo['isInAlexaTop'] or hostInfo['isip'] or not hostInfo['isvaliddomain']:
                continue

            if len(hostInfo['subhost_parts']) !=1 or max(hostInfo['subhost_parts']) != 1:
                continue

            #xz.
            #comment	domain	cnt_hosts	cnt_urls	cnt_hosts/cnt_urls	subhost_parts	host_max_len	host_min_len
            #black, 漏报，domain_hosts角度的cnt_hosts应该检出	hblyny.com	57	699	0.004291845	1	13	13
            if hostInfo['host_min_len'] - len(domain) < 3:
                continue

            if hostInfo['cnt_hosts'] < 10:
                continue

            if hostInfo['cnt_hosts'] > 20:
                self.s_suspiciousDomain[domain].add(SUSPICIOUS_TYPE_DOMAIN_HOSTS)

    def judgeSuspicious_ByDomainNew(self, filename):
        self.doStat_Domain_Hosts(filename)

        suspicious_type = SUSPICIOUS_TYPE_DOMAIN_NEW
        for domain, hostInfo in self.d_domain_hosts.iteritems():
            if hostInfo['isInAlexaTop'] or not hostInfo['isvaliddomain']: # or hostInfo['isip'] :
                continue

            if not self.hitDomain(domain):
                #not new domain
                continue

            if hostInfo['cnt_urls'] < 5:
                continue

            checkFileType = ['apk','zip', 'rar']
            hitFileType = True
            for filetype in list(hostInfo['filetype']):
                if filetype.lower() not in checkFileType:
                    hitFileType = False
                    break

            if not hitFileType:
                continue

            self.s_suspiciousDomain[domain].add(SUSPICIOUS_TYPE_DOMAIN_NEW)


    def judgeSuspicious_ByDomainURLS(self, filename):
        self.doStat_Domain_Hosts(filename)

        suspicious_type = "domain_urls"
        for domain, hostInfo in self.d_domain_hosts.iteritems():
            if hostInfo['isInAlexaTop'] or hostInfo['isip'] or not hostInfo['isvaliddomain']:
                continue

            checkFileType = ['apk', 'exe', 'txt', 'png', 'gif', 'rar']
            '''
            if hostInfo['cnt_filetype'] != 1:
                continue

            if list(hostInfo['filetype'])[0].lower() not in checkFileType:
                continue
            '''
            hitFileType = True
            for filetype in list(hostInfo['filetype']):
                if filetype.lower() not in checkFileType:
                    hitFileType = False
                    break

            if not hitFileType:
                continue

            if hostInfo['cnt_hosts'] < 5:
                continue

            if hostInfo['cnt_hosts'] * 1.0 / hostInfo['cnt_urls'] < 0.5:
                continue

            if hostInfo['sub_max_len'] * 1.0 / hostInfo['host_max_len'] < 0.3:
                continue

            #whether the string is meaningful, or just a random string
            #TBD

            #whether cname
            non_exists = generateRandomString(6)
            print domain
            cmd = 'ping -n 3 %s.%s'%(non_exists, domain)
            ret = subprocess.call(cmd, shell=True)
            if 1 == ret:
                continue

            self.s_suspiciousDomain[domain].add(SUSPICIOUS_TYPE_DOMAIN_URLS)

    def dumpSuspicious_Domain_Hosts(self, filename):
        self.doStat_Domain_Hosts(filename)

        self.judgeSuspicious_ByDomainHosts(filename)
        self.judgeSuspicious_ByDomainURLS(filename)
        self.judgeSuspicious_ByKeyWords(filename)
        self.judgeSuspicious_ByDomainNew(filename)

        fw = open(filename + '_suspicious_for_wd.txt', 'wb')
        for domain in self.s_suspiciousDomain:
            hostInfo = self.d_domain_hosts[domain]
            url = list(hostInfo['urls'])[0][:100]

            infoAry = [domain, url]
            fw.write('%s\t'%('|'.join(self.s_suspiciousDomain[domain])))
            fw.write('%s'%('|'.join(infoAry)))
            try:
                fw.write('\t%s'%(self.d_sus_domain_keyword[domain]))
            except:
                pass
            fw.write('\n')
        fw.close()

    def doStat_Domain_Hosts(self, filename):
        if self.d_domain_hosts:
            return

        fr = open(filename, 'rb')
        for line in fr:
            url = urllib.unquote(line.strip())

            try:
                #remove cdn manually, and the url returned with be used
                url = self.urlchecker.removeCDN(url)
                host, port, subhost, domain, tld, isip, isvaliddomain = self.urlchecker.getHostInfo(url, False)
                host[0]
            except:
                continue

            isInAlexaTop = self.url_util.isDomainInAlexTop(domain)

            #extract urlkeywords
            self.extractUrlKeywords(url, domain, isInAlexaTop)

            if domain not in self.d_domain_hosts:
                self.d_domain_hosts[domain] = {'isip':isip,
                                               'isvaliddomain' : isvaliddomain,
                                               'isInAlexaTop': isInAlexaTop,
                                               'cnt_hosts': 0,
                                               'subhost_parts': set(),     #how many . within subhost
                                               'host_max_len' : len(host),
                                               'host_min_len' : len(host),
                                               'sub_max_len' : 0,
                                               'hosts' : set(),
                                               'cnt_urls' : 0,  #all the urls count for this domain
                                               'urls' : set(),  #only one for each filetype
                                               'filetype': set(),
                                               'cnt_filetype' : 0,
                                               'path_best': set(),
                                               'cnt_path_best' : 0,
                                               'percent_part_host': 0.0,
                                               'percent_host_url': 0.0
                                               }
            self.d_domain_hosts[domain]['hosts'].add(host)
            self.d_domain_hosts[domain]['sub_max_len'] = max(self.d_domain_hosts[domain]['sub_max_len'], max(map(len, subhost.split('.'))))
            self.d_domain_hosts[domain]['cnt_urls'] += 1
            self.d_domain_hosts[domain]['subhost_parts'].add(subhost.count('.'))

            path_best = URLChecker_Util.getPath_Best(url)
            self.d_domain_hosts[domain]['path_best'].add(path_best)

            filetype = self.url_util.getFileType(url)
            if filetype not in self.d_domain_hosts[domain]['filetype']:
                self.d_domain_hosts[domain]['filetype'].add(filetype)
                self.d_domain_hosts[domain]['cnt_filetype'] += 1
                self.d_domain_hosts[domain]['urls'].add(url)

                max_hostpart = max(map(len, host.split('.')))
                self.d_domain_hosts[domain]['percent_part_host'] = max_hostpart * 1.0 / len(host)
                self.d_domain_hosts[domain]['percent_host_url'] = len(host) * 1.0 / len(url)

            if isip or not isInAlexaTop:
                continue

            #deal with alexa top
            directInAlexaTop = self.url_util.isDirectInAlexTop(domain, host)
            inAlexaTop = 'direct'
            if (not directInAlexaTop):
                inAlexaTop = 'indirect'

            if host not in self.d_hostInAlexaTop_urls:
                self.d_hostInAlexaTop_urls[host] = {'domain' : domain,
                                                    'inAlexa' : inAlexaTop,
                                                    'urls' : set()}
            self.d_hostInAlexaTop_urls[host]['urls'].add(url)
        fr.close()

        for domain in self.d_domain_hosts:
            self.d_domain_hosts[domain]['cnt_hosts'] = len(self.d_domain_hosts[domain]['hosts'])
            self.d_domain_hosts[domain]['host_max_len'] = max(map(len, self.d_domain_hosts[domain]['hosts']))
            self.d_domain_hosts[domain]['host_min_len'] = min(map(len, self.d_domain_hosts[domain]['hosts']))
            self.d_domain_hosts[domain]['cnt_path_best'] = len(self.d_domain_hosts[domain]['path_best'])

    def dumpStat_Domain_Hosts(self, filename):
        self.doStat_Domain_Hosts(filename)

        fw_domain_hosts = open(filename + '_stat_domain_hosts.txt', 'wb')
        fw_domain_hosts_hdr = open(filename + '_stat_domain_hosts_hdr.txt', 'wb')
        hdrAry = ['total', 'riskpercent','new', 'comment', 'domain', 'isDomainInAlexTop', 'cnt_hosts', 'cnt_urls', 'cnt_hosts/cnt_urls',
                  'subhost_parts', 'host_max_len', 'host_min_len', 'min/max',
                  'sub_max_len', 'sub/max',
                  'part/host', 'host/url',
                  'cnt_filetype', 'cnt_path_best',
                  'isvaliddomain', '_domain_']
        fw_domain_hosts.write('\t'.join(hdrAry) + '\n')
        fw_domain_hosts_hdr.write('\t'.join(hdrAry) + '\n')

        sorted_domain_hosts = sorted(self.d_domain_hosts.items(), key=lambda item: len(item[1]['hosts']), reverse=True)
        for item in sorted_domain_hosts:
            domain = item[0]
            hostInfo = item[1]

            if hostInfo['isip'] or hostInfo['isInAlexaTop']:
                continue

            black = ''
            if domain in self.s_suspiciousDomain:
                black = 'black by engine: ' + ' '.join(self.s_suspiciousDomain[domain])

            new = ''
            if self.hitDomain(domain):
                new = 'new'

            risk = '\t'.join(['', ''])
            if domain in self.domain_level:
                risk = self.domain_level[domain]

            hdrAry = [risk, new, black, domain, hostInfo['isInAlexaTop'], hostInfo['cnt_hosts'], hostInfo['cnt_urls'], hostInfo['cnt_hosts'] * 1.0 / hostInfo['cnt_urls'],
                      ','.join(str(p) for p in hostInfo['subhost_parts']), hostInfo['host_max_len'], hostInfo['host_min_len'], hostInfo['host_min_len'] * 1.0 / hostInfo['host_max_len'],
                      hostInfo['sub_max_len'], hostInfo['sub_max_len'] * 1.0 / hostInfo['host_max_len'],
                      hostInfo['percent_part_host'], hostInfo['percent_host_url'],
                      hostInfo['cnt_filetype'], hostInfo['cnt_path_best'],
                      hostInfo['isvaliddomain'], '_domain_'
                    ]
            hdrAry[2:-1] = map(str, hdrAry[2:-1])

            if hostInfo['cnt_filetype'] < 10:
                hdrAry.append('\t'.join(hostInfo['filetype']))

            if hostInfo['cnt_path_best'] < 10:
                hdrAry.append('\t'.join(hostInfo['path_best']))

            fw_domain_hosts.write("%s\n"%('\t'.join(hdrAry)))
            fw_domain_hosts_hdr.write("%s\n"%('\t'.join(hdrAry)))
            for host in hostInfo['hosts']:
                fw_domain_hosts.write("\t%s\n"%host)
            for url in hostInfo['urls']:
                fw_domain_hosts.write("\t%s\n"%url)
        fw_domain_hosts.close()
        fw_domain_hosts_hdr.close()

    def doSimpleStat(self, filename):
        '''
        do statistics about all the urls within filename,

        filename.txt
            ==> filename.txt_domain.txt             all domains within filename.txt
                filename.txt_domain_hosts.txt       domain and its hosts info within filename
                filename.txt_white_direct.txt       all urls whose host is directly in alex_top_1m, there are absolute safe
                filename.txt_white_indirect.txt     all urls whose host is indirectly in alex_top_1m, there are probably safe
                filename.txt_black.txt              all urls whose host is not in alex_top_1m, there are unknown, gray, or black
                                                        need to be checked
        '''
        fw_white_direct = open(filename + '_white_direct.txt', 'wb')
        fw_white_indirect = open(filename + '_white_indirect.txt', 'wb')
        fw_unknown = open(filename + '_unknown.txt', 'wb')
        fw_alexa_top_domain = open(filename + '_alexa_top_domain.txt', 'wb')
        s_alexa_top_domain = set()

        fw_domain = open(filename + '_domain.txt', 'wb')
        fw_domain_hosts = open(filename + '_domain_hosts.txt', 'wb')
        fw_hosts = open(filename + '_hosts.txt', 'wb')

        d_domain_hosts = {} # {domain:[hosts, hosts,...]}
        d_domain_urls = {}
        d_host_urls = {}
        d_ip_urls = {}
        d_port_urls = {}
        with open(filename, 'rb') as fr:
            for line in fr:
                if not line.strip():
                    continue

                #php%3Fmod%3Dtag%26id%3D3543.	1	_domain_	_invalid_
                #    bbs.hg707.com%2Fmisc.php%3Fmod%3Dtag%26id%3D3543
                line = urllib.unquote(line.strip())

                host, port, subhost, domain, tld, isip, isvalidDomain = self.urlchecker.getHostInfo(line, True)

                isInAlexaTop = ''
                if self.url_util.isDirectInAlexTop(domain, domain):
                    isInAlexaTop = '_alexa_'

                fw_hosts.write("\t".join([host, domain, isInAlexaTop, str(isip), str(isvalidDomain)]) + '\n')

                d_domain_hosts.setdefault(domain + '\t' + isInAlexaTop, set()).add(host)
                d_domain_urls.setdefault(domain + '\t' + str(isip), set()).add(line)
                d_host_urls.setdefault(host, set()).add(line)
                if port != '80':
                    d_port_urls.setdefault(port, set()).add(line)

                info = line.strip() + '\t' + domain + '\t' + host + '\tisip\n'
                if not isip:
                    info = line.strip() + '\t' + domain + '\t' + host + '\tnotip\n'
                else:
                    d_ip_urls.setdefault(host, set()).add(line.strip())

                if self.url_util.isDirectInAlexTop(domain, host):
                    fw_white_direct.write(info)
                    s_alexa_top_domain.add(domain)
                elif self.url_util.isIndirectInAlexTop(domain, host):
                    fw_white_indirect.write(info)
                    s_alexa_top_domain.add(domain)
                else:
                    fw_unknown.write(info)
        fw_white_direct.close()
        fw_white_indirect.close()
        fw_unknown.close()

        fw_alexa_top_domain.write('\n'.join(s_alexa_top_domain) + '\n')
        fw_alexa_top_domain.close()

        sorted_domain_hosts = sorted(d_domain_hosts.items(), key=lambda item: len(item[1]), reverse=True)
        for item in sorted_domain_hosts:
            domain = item[0]
            hosts = item[1]
            invalidHit = '\n'
            if domain[0] == '.' or domain[-1] == '.':
                invalidHit = '\t_invalid_\n'

            fw_domain.write('%s%s'%(domain, invalidHit))
            fw_domain_hosts.write('%s\t%d\t_domain_%s'%(domain, len(hosts), invalidHit))

            for host in d_domain_hosts[domain]:
                fw_domain_hosts.write('\t%s\n'%host)

        fw_domain.close()
        fw_domain_hosts.close()
        fw_hosts.close()

        dumpInfoCnt(filename + '_domain_urls.txt', d_domain_urls)
        dumpInfoCnt(filename + '_host_urls.txt', d_host_urls)
        dumpInfoCnt(filename + '_ip_urls.txt', d_ip_urls)
        dumpInfoCnt(filename + '_port_urls.txt', d_port_urls)

    def doStatPathBest(self, filename):
        d_pathbest_url = {}
        d_pathbest_domain = {}
        d_pathbest_host = {}
        with open(filename, 'rb') as fr:
            for line in fr:
                if not line.strip():
                    continue

                line = urllib.unquote(line.strip())

                host, port, subhost, domain, tld, isip, isvalidDomain = self.urlchecker.getHostInfo(line)
                path_best = self.url_util.getPath_Best(line)
                d_pathbest_url.setdefault(path_best, set()).add(line)
                d_pathbest_domain.setdefault(path_best, set()).add(domain)
                d_pathbest_host.setdefault(path_best, set()).add(host)

        dumpInfoCnt('dump_path_best.txt', d_pathbest_url)
        dumpInfoCnt('dump_path_best_domain.txt', d_pathbest_domain)
        dumpInfoCnt('dump_path_best_host.txt', d_pathbest_host)

def main():
    obj = URLChecker_Stat()
    #obj.loadNewHostIP()
    #obj.loadDomainLevel()


    obj.doSimpleStat(sys.argv[1])
    #obj.dumpSuspicious_Domain_Hosts(sys.argv[1])
    #obj.dumpStat_Domain_Hosts(sys.argv[1])

    #obj.doStat_Domain_Hosts(sys.argv[1])
    #obj.dumpUrlKeywords()


    #obj.doStatPathBest(sys.argv[1])

if __name__ == "__main__":
    main()
