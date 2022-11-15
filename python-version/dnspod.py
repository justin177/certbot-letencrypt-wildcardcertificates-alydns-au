# coding:utf-8

import hashlib, hmac, json, os, sys, time
from datetime import datetime

class DNSPod:
    def __init__(self, secret_id, secret_key, domain_name):
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.domain_name = domain_name

        self.service = "dnspod"
        self.host = "dnspod.tencentcloudapi.com"
        self.endpoint = "https://" + self.host
        self.region = "ap-shanghai"
        self.version = "2021-03-23"
        self.algorithm = "TC3-HMAC-SHA256"
        self.signed_headers = "content-type;host"
        self.content_type = "application/json; charset=utf-8"

    # ************* 步骤 1：拼接规范请求串 *************
    def build_request(self, payload):
        http_request_method = "POST"
        canonical_uri = "/"
        canonical_querystring = ""
        canonical_headers = "content-type:%s\nhost:%s\n" % (self.content_type, self.host)
        hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        canonical_request = (http_request_method + "\n" +
                             canonical_uri + "\n" +
                             canonical_querystring + "\n" +
                             canonical_headers + "\n" +
                             self.signed_headers + "\n" +
                             hashed_request_payload)
        # print(canonical_request)
        return canonical_request

    # ************* 步骤 2：拼接待签名字符串 *************
    def wait_sign(self, canonical_request, timestamp):
        date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
        credential_scope = date + "/" + self.service + "/" + "tc3_request"
        hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = (self.algorithm + "\n" +
                          str(timestamp) + "\n" +
                          credential_scope + "\n" +
                          hashed_canonical_request)
        # print(string_to_sign)
        return string_to_sign

    # ************* 步骤 3：计算签名 *************
    # 计算签名摘要函数
    @staticmethod
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    def gen_signature(self, string_to_sign, timestamp):
        date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
        secret_date = self.sign(("TC3" + self.secret_key).encode("utf-8"), date)
        secret_service = self.sign(secret_date, self.service)
        secret_signing = self.sign(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        # print(signature)
        return signature


    # ************* 步骤 4：拼接 Authorization *************
    def gen_authorization(self, signature, timestamp):
        date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
        credential_scope = date + "/" + self.service + "/" + "tc3_request"
        authorization = (self.algorithm + " " +
                         "Credential=" + self.secret_id + "/" + credential_scope + ", " +
                         "SignedHeaders=" + self.signed_headers + ", " +
                         "Signature=" + signature)
        # print(authorization)
        return authorization

    def do(self, action, params):
        timestamp = int(time.time())
        payload = json.dumps(params)
        canonical_request = self.build_request(payload)
        string_to_sign = self.wait_sign(canonical_request, timestamp)
        signature = self.gen_signature(string_to_sign, timestamp)
        authorization = self.gen_authorization(signature, timestamp)

        # print('curl -X POST ' + self.endpoint
        #       + ' -H "Authorization: ' + authorization + '"'
        #       + ' -H "Content-Type: ' + self.content_type + '"'
        #       + ' -H "Host: ' + self.host + '"'
        #       + ' -H "X-TC-Action: ' + action + '"'
        #       + ' -H "X-TC-Timestamp: ' + str(timestamp) + '"'
        #       + ' -H "X-TC-Version: ' + self.version + '"'
        #       + ' -H "X-TC-Region: ' + self.region + '"'
        #       + " -d '" + payload + "'")

        if sys.version_info[0] < 3:
            import urllib2
            from urllib2 import URLError, HTTPError
            from contextlib import closing
            req = urllib2.Request(url=self.endpoint, data=payload.encode("utf-8"))
            req.get_method = lambda: "POST"
            req.add_header('Authorization', authorization)
            req.add_header('Content-Type', self.content_type)
            req.add_header('Host', self.host)
            req.add_header('X-TC-Action', action)
            req.add_header('X-TC-Timestamp', str(timestamp))
            req.add_header('X-TC-Version', self.version)
            try:
                with closing(urllib2.urlopen(req)) as res:
                    code = res.getcode()
                    # print(res.info())
                    resinfo = res.read().decode('utf-8')
                    if code != 200:
                        return False, resinfo
                    else:
                        m = json.loads(resinfo)
                        return True, m
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
            req = urllib.request.Request(url=self.endpoint, data=payload.encode("utf-8"), method="POST")
            req.add_header('Authorization', authorization)
            req.add_header('Content-Type', self.content_type)
            req.add_header('Host', self.host)
            req.add_header('X-TC-Action', action)
            req.add_header('X-TC-Timestamp', str(timestamp))
            req.add_header('X-TC-Version', self.version)
            try:
                with closing(urllib.request.urlopen(req)) as res:
                    code = res.getcode()
                    # print(res.info())
                    resinfo = res.read().decode('utf-8')
                    if code != 200:
                        return False, resinfo
                    else:
                        m = json.loads(resinfo)
                        return True, m
            except (HTTPError, URLError) as e:
                return False, str(e)


    @staticmethod
    def get_domain(domain):
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
            return selfdomain[0:len(selfdomain) - 1], rootdomain
        return "", domain

    def create_dns_record(self, name, value, record_type='TXT'):
        data = {
            "Domain": self.domain_name,
            "SubDomain": name,
            "Value": value,
            "RecordType": record_type,
            "RecordLine": "默认",
            "TTL": 600
        }
        return self.do('CreateRecord', data)

    def get_dns_record(self, name, record_type='TXT'):
        data = {"Domain": self.domain_name, "Subdomain": name, "RecordType": record_type}
        return self.do('DescribeRecordList', data)

    def delete_dns_record(self, name, record_type='TXT'):
        success, get_result = self.get_dns_record(name, record_type)
        if (not success) or ("Response" not in get_result) or ("RecordList" not in get_result["Response"]):
            return False
        for record in get_result["Response"]["RecordList"]:
            data = {"Domain": self.domain_name, "RecordId": record["RecordId"]}
            success, result = self.do('DeleteRecord', data)
            print (success, result)
        return True


file_name, cmd, certbot_domain, acme_challenge, certbot_validation, secret_id, secret_key = sys.argv

certbot_domain = DNSPod.get_domain(certbot_domain)
if certbot_domain[0] == "":
    selfdomain = acme_challenge
else:
    selfdomain = acme_challenge + "." + certbot_domain[0]

domain = DNSPod(secret_id, secret_key, certbot_domain[1])

if cmd == "add":
    print(domain.create_dns_record(selfdomain, certbot_validation))

if cmd == "clean":
    print(domain.delete_dns_record(selfdomain))

if cmd == "get":
    print(domain.get_dns_record(selfdomain))
