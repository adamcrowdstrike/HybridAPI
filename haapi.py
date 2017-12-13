#!/usr/bin/env python
# Author: Adam Meyers

import requests
from requests.auth import HTTPBasicAuth
import sys
import optparse
from time import sleep

class hybridapi():
    def __init__(self, api, key):
        self.api = api
        self.key = key

    def search_ha(self,shahash):
      self.url = "https://www.hybrid-analysis.com/api/scan/"
      self.headers = {'User-Agent': 'VxApi Connector'}
      self.query = "%s%s" % (self.url, shahash)
      self.r = requests.get(self.query, headers=self.headers, auth=HTTPBasicAuth(self.api, self.key))
      return self.r.json()

    def search_hadata(self,data):
      self.url = "https://www.hybrid-analysis.com/api/search?query="
      self.headers = {'User-Agent': 'VxApi Connector'}
      self.query = "%s%s" % (self.url, data)
      self.r = requests.get(self.query, headers=self.headers, auth=HTTPBasicAuth(self.api, self.key))
      return self.r.json()

    def querydata(self,shahash):
      return self.search_ha(shahash)

    def queryioc(self,indicator):
      return self.search_hadata(indicator)

def report(data):
    try:
        print "Sha256 - %s" % data['response'][0]['sha256']
        print "\tSubmission Name: %s" % data['response'][0]['submitname']
        print "\tVXFamily: %s" % data['response'][0]['vxfamily']
        print "\tScan Time: %s" % data['response'][0]['analysis_start_time']
        print "\tFile Type: %s" % data['response'][0]['type']
        print "\tC2 Domains: %s" % data['response'][0]['domains']
        print "\tC2 Hosts: %s" % data['response'][0]['hosts']
    except:
        print data

def main():
    api, key = ('<api>','<key>')
    opt=optparse.OptionParser()
    opt.add_option("-d", "--dns", dest="dns", help="Query a DNS against Hybrid-Analysis")
    opt.add_option("-i", "--ipv4", dest="ip", help="Query a IP against Hybrid-Analysis")
    opt.add_option("-t", "--type", dest="type", help="Query a File Type from Hybrid-Analysis")
    opt.add_option("-s", "--sha", dest="sha", help="Query a Sha256 from Hybrid-Analysis")
    opt.add_option("-v", "--vxfamily", dest="vxfam", help="Query a VXFamily from Hybrid-Analysis")
    options, args= opt.parse_args()
    ha=hybridapi(api,key)
    if options.dns:
        query = ha.queryioc('domain:%s' %options.dns)
        if query != False:
            for x in query['response']['result']:
                report(ha.querydata(x['sha256']))
                sleep(12)
    elif options.ip:
        query = ha.queryioc('host:%s' %options.ip)
        print options.ip
        if query != False:
            for x in query['response']['result']:
                report(ha.querydata(x['sha256']))
                sleep(12)
    elif options.type:
        query = ha.queryioc('filetype_tag:%s' %options.type)
        print options.type
        if query != False:
            for x in query['response']['result']:
                report(ha.querydata(x['sha256']))
                sleep(12)
    elif options.sha:
        query = ha.querydata(options.sha)
        print options.sha
        if query != False:
            report(query)
    elif options.vxfam:
        query = ha.queryioc('vxfamily:%s' %options.vxfam)
        print options.vxfam
        if query != False:
            for x in query['response']['result']:
                report(ha.querydata(x['sha256']))
                sleep(12)
    else:
        opt.print_help()

if __name__ == '__main__':
  main()
