import sys
from URLChecker import *
from URLChecker_Util import *

class FilterDomain:
    def __init__(self):
        self.urlchecker = URLChecker()
        self.url_util = URLChecker_Util()

    def isExclude(self, host):
        if len(host) < 6:
            return True

        if self.url_util.isInWhiteList(host):
            return True

        #tmp_host, port, subhost, domain, tld, isip, isvaliddomain = self.urlchecker.getHostInfo(url, False)






def main():
    host = 'www.yourbigandgoodtoupdates.club'
    tmp_host, port, subhost, domain, tld, isip, isvaliddomain = URLChecker().getHostInfo(host, False)
    print(domain)
    pass

if __name__ == "__main__":
    main()
