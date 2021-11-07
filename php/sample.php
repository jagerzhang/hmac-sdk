<?php
include("hmac_auth.php");

// 请根据实际情况修改
$username = '<hmac 账号>';
$secret = '<hmac 密钥>';
$url = '<带hmac鉴权的接口地址>';
 
$params = json_encode(array(
    'params' => array(
        'foo' => 'bar'
    ),
));
$headers = HmacAuth::get_auth_header($username, $secret);
 
// 请求
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
 
$result = curl_exec($ch);
echo $result;
