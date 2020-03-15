<?php
/**
   Kong 网关 Hmac 认证类 by Calzhang
**/
class KongHmac
{
    public static function get_auth_header($username = '', $secret = '', $body = '')
    {
        // 生成body的sha256加密串
        $body_digest = 'SHA-256=' . base64_encode(hash('sha256', $body, true));
        // 生成当前GMT时间，注意格式不能改变，必须形如：Wed, 14 Aug 2019 09:09:28 GMT
        $gmt_time = gmdate('D, d M Y H:i:s T');
        // 生产签名
        $sinature = base64_encode(hash_hmac('sha256', "date: {$gmt_time}\ndigest: {$body_digest}", $secret, true));
        $headers = array(
            "Authorization: hmac username=\"{$username}\", algorithm=\"hmac-sha256\", headers=\"date digest\", signature=\"{$sinature}\"",
            "Digest: {$body_digest}",
            "Date: $gmt_time",
            "Content-Type: application/json",
        );
        return $headers;
    }
}
