# -*- coding: utf8 -*-
import json
import requests
# for python2.X
from kong_hmac_py2 import KongHmac
# for python3.X
# from kong_hmac_py3import KongHmac

if __name__ == "__main__":
    # 根据实际情况修改
    username = "<username>"
    secret = "<secret>"
    api_url = "http://<apiname>.apigw.tencent-cloud.com/<path>"
    param = {"prams":{
                "xxxx":"xxx"
            }}
    kong_hmac = KongHmac()
    # 请求的参数和拿去生成签名的参数保持一致，否则内容校验会失败：
    param = json.dumps(param)
    headers = kong_hmac.get_auth_header(username=username,secret=secret,body=param)
    headers["Content-Type"] = "application/json"
    print(headers)
    resp = requests.post(url=api_url, data=param, headers=headers)
    print(resp.text)
