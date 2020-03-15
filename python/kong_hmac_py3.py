# -*- coding: utf8 -*-
__author__ = 'Jagerzhang'
import requests
import json
import time
import hmac
import hashlib
import base64
 
 
class KongHmac():
    """生成Kong的Hmac鉴权头部
    仅适配了hmac-sha256加密方式
    """
 
    def sha256_digest_base64(self, content):
        """ sha256计算内容摘要
        """
        content_bytes = bytes(content,"utf-8")
        # content_bytes = content
        content_sha256_digest = hashlib.sha256(content_bytes).digest()
        content_sha256_digest_base64_decode = base64.b64encode(content_sha256_digest).decode()
        content_digest = 'SHA-256={}'.format(content_sha256_digest_base64_decode)
        return content_digest
 
    def hmac_sha256_base64(self, secret, str_to_sign):
        """ 生成sha256加密串
        """
        signature = hmac.new(bytes(secret,"utf-8"), bytes(str_to_sign,"utf-8"),
                             digestmod=hashlib.sha256).digest()
        str_base64 = base64.b64encode(signature).decode()
        return str_base64
 
    def get_auth_header(self, username, secret, body):
        # 生成body的sha256加密串
        body_digest = self.sha256_digest_base64(body)
 
        # 生成当前GMT时间，注意格式不能改变，必须形如：Wed, 14 Aug 2019 09:09:28 GMT
        gm_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
 
        # 拼装待签名的数据
        str_to_sign = "date: {}\ndigest: {}".format(gm_time, body_digest)
 
        # 生成签名
        signature = self.hmac_sha256_base64(secret, str_to_sign)
 
        # 拼装headers
        headers = {
            'Authorization': 'hmac username=\"{}\", algorithm=\"hmac-sha256\", headers=\"date digest\", '
                             'signature=\"{}\"'.format(username, signature),
            'Digest': body_digest,
            'Date': gm_time}
        return headers
 
 
if __name__ == "__main__":
    # 根据实际情况修改
    username = "<username>"
    secret = "<secret>"
    sdn_api = "http://tix-gn.sdn-api.tencent-cloud.com/restconf/operations/route-adjust:get-adjust-history-list"
    param = {"input": {
        "startTime": "2020-02-01-00-00-00",
        "endTime": "2020-02-13-18-00-00"
    }}
    kong_hmac = KongHmac()
    # 请求的参数和拿去生成签名的参数保持一致，否则内容校验会失败：
    param = json.dumps(param)
    headers = kong_hmac.get_auth_header(username=username, secret=secret, body=param)
    headers["Content-Type"] = "application/json"
    resp = requests.post(url=sdn_api, data=param, headers=headers)
    print (resp.text)
