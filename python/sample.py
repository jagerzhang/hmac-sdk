# -*- coding: utf8 -*-
import requests
from hmac_auth import HmacAuth

if __name__ == "__main__":
    # 根据实际情况修改
    USERNAME = "<HMAC 账号>"
    SECRET = "<HMAC 密钥>"
    API_URL = "<带hmac鉴权的接口地址>"
    param = {"xxx": {"xxxx": "xxx"}}

    # 方式一：在初始化class的时候设置账号密钥
    hmac_auth = HmacAuth(hmac_user=USERNAME, hmac_secret=SECRET)
    headers = hmac_auth.get_auth_headers()

    # 方式二：在生成头部的时候设置账号密钥
    # hmac_auth = HmacAuth()
    # headers = hmac_auth.get_auth_headers(hmac_user=USERNAME, hmac_secret=SECRET)

    resp = requests.post(url=API_URL, json=param, headers=headers)

    if resp.status_code == 200:
        exit("Test OK!")

    else:
        print(headers)
        print(resp.text)
        exit("Test Failed!")
