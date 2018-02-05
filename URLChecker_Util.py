# -*- coding: utf-8 -*-
import sys
import re
import socket
import pickle
import logging
import os
import urllib

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

LOG = logging.getLogger("urlchecker")

SCHEME_RE = re.compile(r'^([' + scheme_chars + ']+:)?//')
IP_RE = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

invalid_prog = re.compile('[^%s:]'%scheme_chars)

class URLChecker_Util:
    #use this as static variable
    alex_top = None
    tld_cache = None
    whitelist = None

    def __init__(self, TLD_CACHED_FILE='tld_cache.dat', ALEX_TOP_CACHED_FILE='alex_top_1m.txt', WHITELIST_FILE='meta_hosts.txt'):
        self.TLD_CACHED_FILE = TLD_CACHED_FILE
        self.ALEX_TOP_CACHED_FILE = ALEX_TOP_CACHED_FILE
        self.WHITELIST_FILE = WHITELIST_FILE

        self.env_init()

        URLChecker_Util.alex_top = self.getAlexTopByCache()
        URLChecker_Util.tld_cache = self.getTLDS()
        URLChecker_Util.whitelist = self.getWhiteList()

    def env_init(self):
        dirname = os.path.dirname(__file__)

        self.TLD_CACHED_FILE = os.path.join(dirname, self.TLD_CACHED_FILE)
        self.ALEX_TOP_CACHED_FILE = os.path.join(dirname, self.ALEX_TOP_CACHED_FILE)

    @staticmethod
    def isValidHost(host):
        if invalid_prog.search(host):
            return False
        return True

    @staticmethod
    def isip(host):
        try:
            socket.inet_aton(host)
            return True
        except AttributeError:
            if IP_RE.match(host):
                return False
        except socket.error:
            return False

    @staticmethod
    def getHostInfo(url):
        '''
        https://tools.ietf.org/html/rfc3986
        https://tools.ietf.org/html/rfc1808

        <scheme>://<net_loc>/<path>;<params>?<query>#<fragment>

        <scheme>://<user>:<password>@<host>:<port>/<url-path>

         foo://example.com:8042/over/there?name=ferret#nose
             \_/   \______________/\_________/ \_________/ \__/
              |           |            |            |        |
           scheme     authority       path        query   fragment
              |   _____________________|__
             / \ /                        \
             urn:example:animal:ferret:nose

        the authority component is precended by a double slash ("//")
            and is terminated by the next slash ("/"), question mark ("?"), or number sign ("#") character

        '''
        urls = url.split()
        if len(urls) == 0:
            return ('', '', False)
        netloc = SCHEME_RE.sub("", url) \
                .partition("/")[0] \
                .partition("?")[0] \
                .partition("#")[0] \
              # / ? and # as the end anchor

        hostport = netloc.split("@")[-1] # remove user, password
        (host, sep, port)= hostport.partition(":")
        if not URLChecker_Util.isValidHost(host):
            return ('', '', False)

        if not port:
            port = '80'
        return (host, port, URLChecker_Util.isip(host))

    @staticmethod
    def removeScheme(url):
        '''
        http://www.360.cn/xx.html ==> www.360.cn/xx.html
        https://www.360.cn/xx.html ==> www.360.cn/xx.html
        '''
        return SCHEME_RE.sub("", url)

    @staticmethod
    def _fetch_page(url):
        try:
            return unicode(urlopen(url).read(), 'utf-8')
        except URLError as e:
            return u''

    @staticmethod
    def _PublicSuffixListSource():
        page = URLChecker_Util._fetch_page('http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1')

        tld_finder = re.compile(r'^(?P<tld>[.*!]*\w[\S]*)', re.UNICODE | re.MULTILINE)
        tlds = [m.group('tld') for m in tld_finder.finditer(page)]
        return tlds

    @staticmethod
    def removeQuery(url):
        return re.split('[?&=#]', url)[0]

    @staticmethod
    def getFileType(url):
        filetype = url.rpartition('/')[2]
        if not filetype:
            return 'apk'

        filetype = URLChecker_Util.removeQuery(filetype)
        filetype = filetype.rpartition('.')[2]
        if not filetype:
            return 'apk'

        return filetype

    def getTLDSByFly(self):
        '''
        download suffix dat from web and save to local cache.

        hackpoint: here use _PublicSuffixListSource as a function ptr, make it a convenient way to call someone.
        '''
        tld_sources = (URLChecker_Util._PublicSuffixListSource,)
        tlds = frozenset(tld for tld_source in tld_sources for tld in tld_source())

        try:
            with open(self.TLD_CACHED_FILE, 'wb') as f:
                pickle.dump(tlds, f)
        except IOError as e:
            LOG.warn("unable to cache TLDs in file %s: %s", TLD_CACHED_FILE, e)
        return tlds

    def getTLDSByCache(self):
        tlds = frozenset()
        with open(self.TLD_CACHED_FILE) as f:
            tlds = pickle.load(f)
        return tlds

    def getTLDS(self, isForceUpdate = False):
        if not isForceUpdate and URLChecker_Util.tld_cache:
            return URLChecker_Util.tld_cache

        URLChecker_Util.tld_cache = frozenset()
        URLChecker_Util.tld_cache = self.getTLDSByCache()
        if not URLChecker_Util.tld_cache or isForceUpdate:
            URLChecker_Util.tld_cache = getTLDSByFly()
        return URLChecker_Util.tld_cache

    def getAlexTopByCache(self):
        '''
        http://s3.amazonaws.com/alexa-static/top-1m.csv.zip

        alex_top_1m.txt is the white domain
        '''
        if URLChecker_Util.alex_top:
            return URLChecker_Util.alex_top

        URLChecker_Util.alex_top = set()
        with open(self.ALEX_TOP_CACHED_FILE) as fr:
            for line in fr:
                URLChecker_Util.alex_top.add(line.strip())
        return URLChecker_Util.alex_top

    def getWhiteList(self):
        URLChecker_Util.whitelist = set()
        with open(self.WHITELIST_FILE) as fr:
            for line in fr:
                URLChecker_Util.whitelist.add(line.strip())
        return URLChecker_Util.whitelist

    def isInWhiteList(self, host):
        return host in URLChecker_Util.whitelist

    def isDomainInAlexTop(self, domain):
        return domain in URLChecker_Util.alex_top

    def isDirectInAlexTop(self, domain, host):
        '''
        @param: make sure that is the host

        if 360.cn in alextop, then 360.cn and www.360.cn will both in
        '''
        if not self.isDomainInAlexTop(domain):
            return False

        if domain == host or 'www.' + domain == host:
            return True
        return False

    def isIndirectInAlexTop(self, domain, host):
        '''
        if blogspot.com in alextop, then xx.blogspot.com will 'subin' or indirect in
        '''
        if not self.isDomainInAlexTop(domain):
            return False

        if self.isDirectInAlexTop(domain, host):
            return False
        return True

    @staticmethod
    def getPath2(url):
        '''
        get the last 2 parts splitted by /
        '''
        url = URLChecker_Util.removeQuery(url)
        items = url.strip().split('/')
        return '/'.join(items[-2:])

    @staticmethod
    def getPath_r2_3(url):
        url = URLChecker_Util.removeQuery(url)
        items = url.strip().split('/')
        if len(items) < 4:
            return url
        return '/'.join(items[-3:-1])

    @staticmethod
    def getPath_Best(url):
        url = URLChecker_Util.removeQuery(url)
        items = url.strip().split('/')
        cnt = len(items)
        if cnt < 2:
            return url
        if cnt == 3:
            return URLChecker_Util.getPath2(url)

        return URLChecker_Util.getPath2(url)
        #return URLChecker_Util.getPath_r2_3(url)

    def extract(self, netloc):
        '''
        make sure netloc is valid, not the url

        return tuple(registered_domain, tld)
        '''
        spl = netloc.split('.')
        lower_spl = tuple(el for el in spl)
        for i in range(len(spl)):
            maybe_tld = '.'.join(lower_spl[i:])

            '''
            // ck : https://en.wikipedia.org/wiki/.ck
            *.ck
            !www.ck

            so,
            www.ck ==> ('www', 'ck')
            any.ck ==> ('', 'any.ck')
            '''
            exception_tld = '!' + maybe_tld
            if exception_tld in URLChecker_Util.tld_cache:
                return '.'.join(spl[:i+1]), '.'.join(spl[i+1:])

            if maybe_tld in URLChecker_Util.tld_cache:
                return '.'.join(spl[:i]), '.'.join(spl[i:])

            wildcard_tld = '*.' + '.'.join(lower_spl[i+1:])
            if wildcard_tld in URLChecker_Util.tld_cache:
                return '.'.join(spl[:i]), '.'.join(spl[i:])

        return netloc, ''

def main():
    obj = URLChecker_Util()
    '''
    #print URLChecker_Util.getFileType(sys.argv[1])
    print URLChecker_Util.getPath2(sys.argv[1])
    print URLChecker_Util.getPath_r2_3(sys.argv[1])
    print URLChecker_Util.getPath_Best(sys.argv[1])

    print URLChecker_Util.getHostInfo(sys.argv[1])
    print obj.isDomainInAlexTop(sys.argv[1])
    print obj.isDirectInAlexTop(sys.argv[1], sys.argv[2])
    print obj.isIndirectInAlexTop(sys.argv[1], sys.argv[2])
    '''
    print obj.extract(sys.argv[1])
    print URLChecker_Util.getHostInfo(sys.argv[1])
    print URLChecker_Util.isValidHost(sys.argv[1])
    print obj.isInWhiteList(sys.argv[1])


if __name__ == "__main__":
    main()
