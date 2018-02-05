import os

def isCached(extra):
    fname = '%s_%d'%(extra['cur_query'], extra['page'])
    if os.path.isfile(fname):
        return True
    return False

def doCache(extra):
    fname = '%s_%d'%(extra['cur_query'], extra['page'])
    open(fname, 'a').close()
