# -*- coding: utf8 -*-
__author__ = 'Jager'
import sys
import hmac
import hashlib
import base64
import time


class HmacAuth():
    """生成Hmac(hmac-sha256)鉴权头部
    :param hmac_user, String, 可选, 在class初始化时预设HMAC账号，可被函数覆盖
    :param hmac_secret, String, 可选, 在class初始化时预设HMAC密钥，可被函数覆盖
    :return Class Object
    """
    def __init__(self, hmac_user=None, hmac_secret=None):
        self.hmac_user = hmac_user
        self.hmac_secret = hmac_secret

    def _sha256_digest(self, content):
        """ sha256计算内容摘要
        :param content, String, 内容
        """
        if sys.version_info.major > 2:
            content_bytes = bytes(content, "utf-8")

        else:
            content_bytes = bytes(content).decode("utf-8")

        content_sha256_digest = hashlib.sha256(content_bytes).digest()
        content_sha256_digest_base64_decode = base64.b64encode(
            content_sha256_digest).decode()
        content_digest = 'SHA-256={}'.format(
            content_sha256_digest_base64_decode)
        return content_digest

    def _hmac_sha256(self, secret, str_to_sign):
        """生成sha256加密串
        :param secret, String, 指定密钥
        :param str_to_sign, String, 已拼装待签名的数据
        """
        if sys.version_info.major > 2:
            hmac_key = bytes(secret, "utf-8")
            msg_sign = bytes(str_to_sign, "utf-8")

        else:
            hmac_key = bytes(secret)
            msg_sign = bytes(str_to_sign)

        signature = hmac.new(hmac_key, msg_sign,
                             digestmod=hashlib.sha256).digest()
        str_base64 = base64.b64encode(signature).decode()
        return str_base64

    def get_auth_headers(self, hmac_user=None, hmac_secret=None, body=""):
        """获取Hmac鉴权头部
        :param String, 可选, 指定Hmac账号，可以覆盖class预设的Hmac账号
        :param String, 可选, 指定hmac密钥，可以覆盖class预设的Hmac密钥
        :param String, 可选，指定请求Body内容，当网关要求验签body的时候必传，Get请求则传入空值
        :param Dict, 返回Hmac认证头部字典
        """
        if not hmac_user:
            hmac_user = self.hmac_user

        if not hmac_secret:
            hmac_secret = self.hmac_secret

        # 生成body的sha256加密串
        body_digest = self._sha256_digest(body)

        # 生成当前GMT时间，注意格式不能改变，必须形如：Wed, 14 Aug 2019 09:09:28 GMT
        gm_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

        # 拼装待签名的数据
        str_to_sign = "date: {}\ndigest: {}".format(gm_time, body_digest)

        # 生成签名
        signature = self._hmac_sha256(hmac_secret, str_to_sign)

        # 拼装headers
        headers = {}
        headers["Authorization"] = (
            'hmac username="{}", algorithm="hmac-sha256", headers="date digest",'
            'signature="{}"'.format(hmac_user, signature))
        headers["Digest"] = body_digest
        headers["Date"] = gm_time
        return headers
