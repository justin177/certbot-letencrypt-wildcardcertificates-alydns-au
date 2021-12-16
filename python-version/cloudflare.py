# coding:utf-8

import json
import os
import sys


class Cloudflare:
    def __init__(self, access_key_id, access_key_secret, domain_name):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.domain_name = domain_name
        self.zoneID = self.getZoneID()

    @staticmethod
    def getDomain(domain):
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            dirpath = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            domainfile = dirpath + "/domain.ini"
            domainarr = []
            with open(domainfile) as f:
                for line in f:
                    val = line.strip()
                    domainarr.append(val)

            rootdomain = '.'.join(domain_parts[-(2 if domain_parts[-1] in domainarr else 3):])
            selfdomain = domain.split(rootdomain)[0]
            return (selfdomain[0:len(selfdomain) - 1], rootdomain)
        return ("", domain)

    def curl(self, url, data, method):
        print(url, data, method)
        if sys.version_info[0] < 3:
            import urllib2
            from urllib2 import URLError, HTTPError
            from contextlib import closing
            httpdata = json.dumps(data).encode('utf-8')
            if httpdata == '{}':
                req = urllib2.Request(url=url)
            else:
                req = urllib2.Request(url=url, data=httpdata)
            req.get_method = lambda: method
            req.add_header('accept', 'application/json')
            req.add_header('Content-Type', 'application/json')
            key = "Bearer " + self.access_key_secret
            req.add_header('Authorization', key)
            try:
                with closing(urllib2.urlopen(req)) as res:
                    code = res.getcode()
                    # print(res.info())
                    resinfo = res.read().decode('utf-8')
                    if code != 200:
                        return False, resinfo
                    else:
                        m = json.loads(resinfo)
                        return m['success'], m
            except AttributeError as e:
                print(e)
                # python2 处理 PATCH HTTP 方法的一个Bug，不影响结果
                return True, ''
            except (HTTPError, URLError) as e:
                return False, str(e)

        else:
            import urllib.request
            from urllib.error import URLError, HTTPError
            from contextlib import closing
            httpdata = json.dumps(data).encode('utf-8')
            if httpdata == '{}':
                req = urllib.request.Request(url=url, method=method)
            else:
                req = urllib.request.Request(url=url, data=httpdata, method=method)
            req.add_header('accept', 'application/json')
            req.add_header('Content-Type', 'application/json')
            key = "Bearer " + self.access_key_secret
            req.add_header('Authorization', key)
            try:
                with closing(urllib.request.urlopen(req)) as res:
                    code = res.getcode()
                    # print(res.info())
                    resinfo = res.read().decode('utf-8')
                    if code != 200:
                        return False, resinfo
                    else:
                        m = json.loads(resinfo)
                        return m['success'], m
            except (HTTPError, URLError) as e:
                return False, str(e)

    def getZoneID(self):
        url = "https://api.cloudflare.com/client/v4/zones?name=" + self.domain_name
        result, resinfo = self.curl(url, {}, "GET")
        if not result:
            return ''
        if not resinfo['result'] or not resinfo['result'][0]:
            return ''
        return resinfo['result'][0]['id']

    def CreateDNSRecord(self, name, value, recordType='TXT'):
        url = "https://api.cloudflare.com/client/v4/zones/" + self.zoneID + "/dns_records"
        data = {"content": value, "name": name, "ttl": 3600, "type": recordType}
        return self.curl(url, data, "POST")

    def ListDNSRecord(self, name, recordType='TXT'):
        url = "https://api.cloudflare.com/client/v4/zones/" + self.zoneID + "/dns_records" + \
              "?type=" + recordType + "&name=" + name + '.' + self.domain_name
        return self.curl(url, {}, "GET")

    def GetDNSRecord(self, name, recordType='TXT'):
        result, resinfo = self.ListDNSRecord(name, recordType)
        if not result:
            return result, resinfo
        if not resinfo['result'] or not resinfo['result'][0]:
            return False, ''
        identifier = resinfo['result'][0]['id']
        url = "https://api.cloudflare.com/client/v4/zones/" + self.zoneID + "/dns_records/" + identifier
        return self.curl(url, {}, "GET")

    def DeleteDNSRecord(self, name, recordType='TXT'):
        result, resinfo = self.ListDNSRecord(name, recordType)
        if not result:
            return result, resinfo
        if not resinfo['result'] or not resinfo['result'][0]:
            return False, ''
        identifier = resinfo['result'][0]['id']
        url = "https://api.cloudflare.com/client/v4/zones/" + self.zoneID + "/dns_records/" + identifier
        return self.curl(url, {}, "DELETE")


file_name, cmd, certbot_domain, acme_challenge, certbot_validation, ACCESS_KEY_ID, ACCESS_KEY_SECRET = sys.argv

certbot_domain = Cloudflare.getDomain(certbot_domain)
if certbot_domain[0] == "":
    selfdomain = acme_challenge
else:
    selfdomain = acme_challenge + "." + certbot_domain[0]

domain = Cloudflare(ACCESS_KEY_ID, ACCESS_KEY_SECRET, certbot_domain[1])
# print (domain.GetDNSRecord(selfdomain))

if cmd == "add":
    print(domain.CreateDNSRecord(selfdomain, certbot_validation))

if cmd == "clean":
    print(domain.DeleteDNSRecord(selfdomain))

if cmd == "get":
    print(domain.GetDNSRecord(selfdomain))
