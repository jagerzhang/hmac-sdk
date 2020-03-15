<?php
include("kong_hmac.php");

// 请根据实际情况修改
$username = '<username>';
$secret = '<secret>';
$url = 'http://<kong_api_url>';
 
$params = json_encode(array(
    'params' => array(
        'foo' => 'bar'
    ),
));
$headers = KongHmac::get_auth_header($username, $secret, $params);
 
// curl请求
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
 
$result = curl_exec($ch);
echo $result;
