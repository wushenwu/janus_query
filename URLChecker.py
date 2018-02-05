# -*- coding: utf-8 -*-
import sys
import os
import urllib
from collections import defaultdict
from URLChecker_Util import *

try:
    # Python 2
    from urllib2 import urlopen, URLError
    from urlparse import scheme_chars
except ImportError:
    # Python 3
    from urllib.request import urlopen
    from urllib.error import URLError
    from urllib.parse import scheme_chars
    unicode = str

class URLChecker:
    '''
    frequently used methods:
    '''
    def __init__(self):
        self.url_util = URLChecker_Util()

        self.d_domain_hosts = {}
        self.d_hostInAlexaTop_urls = {}

    def removeCDN(self, oriurl):
        '''
        1)find the last FQDN
        2)if no FQDN exist, find the last ip

        #10.102.3.20/update/files/31710000007F3D77/down.myapp.com/myapp/smart_ajax/com.tencent.android.qqdownloader/991310_22331408_1451062634607.apk
            => down.myapp.com

101     #10.236.6.15/downloadw.inner.bbk.com/sms/upapk/0/com.bbk.appstore/20151009151923/com.bbk.appstore.apk
            => download.inner.bbk.com
        '''
        url = URLChecker_Util.removeScheme(oriurl)
        url = urllib.unquote(url)
        url = url.replace('\n', '').replace('\r', '')

        #this may be an host, but need more check
        items = [item for item in url.split('/')[:-1] if item.find('.') != -1 and item.find('&') == -1 and item.find('?') == -1]
        if not items:
            items = [url]

        lastip = None
        for item in items[::-1]:
            host, port, subhost, domain, tld, isip, isvalidDomain = self.getHostInfo(oriurl=item, needremovecdn=False)
            #45.79.146.48/admin201506/uploadApkFile/rt/20160113/geniusalldata.zip
            if host.endswith('.zip'):
                continue

            #buckets.apps.tclclouds.com/appstore/apk/com.tencent.mm/com.tencent.mm.apk
            #downloadw.inner.bbk.com/sms/upapk/4096/com.iqoo.secure/20161024173040/com.iqoo.secure.apk
            #saufs.coloros.com/patch/CHN/com.oppo.market/5004/com.oppo.market_5.0_5004_all_1610281508.apk
            if host[:4] == 'com.':
                continue

            if isvalidDomain and not isip:
                #the last FQDN as the host
                return ''.join(url.partition(host)[1:])

            if isip and not lastip:
                lastip = host

        #if only has ip, then select the lastip
        if lastip:
            return ''.join(url.partition(lastip)[1:])

        return url

    def getHostInfo(self, oriurl, needremovecdn = True):
        '''
        @param oriurl: can be a anything, netloc, or a whole url

               needremovecdn:

        @return: (host, port, domain, tld, isip, isvalidDomain)

        @note:
            host is FQDN, or you can call submain, like www.360.cn, blogs.360.cn
            domain, like 360.cn

        http://www.baidu.com:8090/xx.html
            =>(www.baidu.com, 8090, baidu.com, www.baidu.com, com, false)
        '''
        isvalidDomain = True
        url = urllib.unquote(oriurl)

        if needremovecdn:
            url = self.removeCDN(url)

        (host, port, isip) = URLChecker_Util.getHostInfo(url)
        if not host:
            return ('', '', '', '', '', False, False)
        if isip:
            return (host, port, host, host, '', isip, isvalidDomain)

        #www.360.cn  ==> ('www.360', 'cn')
        registered_domain, tld = self.url_util.extract(host)
        subdomain, _, domain = registered_domain.rpartition('.')
        domain = '%s.%s'%(domain, tld)

        '''
        // ck : https://en.wikipedia.org/wiki/.ck
        *.ck
        !www.ck

        so do.ck 's tld is '.do.ck',

        221.220.221.1998  's domain will be '1998.'

        thz invalid domain starts or ends with '.'

        //com&cuid=820231&fext=.zip
        '''
        if domain[0] == '.' or domain[-1] == '.' or not URLChecker_Util.isValidHost(host):
            isvalidDomain = False
            return ('', '', '', '', '',  False, False)

        #sub host
        subhost = host.partition(domain)[0]

        return (host, port, subhost, domain, tld, isip, isvalidDomain)


def main():

    objURLCheck = URLChecker()
    print objURLCheck.getHostInfo(sys.argv[1])
    #print objURLCheck.removeCDN(sys.argv[1])

if __name__ == "__main__":
    main()
