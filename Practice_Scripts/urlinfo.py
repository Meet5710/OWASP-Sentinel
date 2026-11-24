#!/usr/bin/env python
# urlinfo.py
# made by s3my0n based on URL_INFO by crypthief

import sys, urllib
from os import system

def Help():
    print '\nUsage: urlinfo.py <url>'
    print '\nExample: urlinfo.py http://microsoft.com'
    print '         urlinfo.py microsoft.com'
    sys.exit()

def Work(site):
    print '\nWorking...'
    try:
        url = urllib.urlopen(site)
        info = url.info()
        if 'Server' in info:
            print '\n%s' % info
        else:
            print '\nCouldn\'t open %s' % site
    except IOError:
        print '\nCouldn\'t open %s' % site
    

def Main():
    if len(sys.argv) != 2:
        Help()
    if 'http://' not in sys.argv[1][:7]:
        URL = 'http://' + sys.argv[1]
    else:
        URL = sys.argv[1]
    Work(URL)

if __name__ == '__main__':
    Main()
