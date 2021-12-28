#!/bin/bash
#################################################################
# Function : 网关HMAC验签头部生成脚本                             
# Author: Jager                                                 
# Last Modify Date :2021-12-12                                  
#################################################################
# 环境依赖：需要安装 openssl (yum install -y openssl)             
# 使用说明：                                                     
# 方式1： 基于脚本参数导入账号和密钥                                                       
#   bash hmac_auth.sh <HMAC_USER> <HMAC_SECRET> [BODY_STRING]   
#   参数1：指定HMAC账号                                          
#   参数2：指定HMAC密钥                                          
#   参数3: 请求Body的字符串内容（可选），默认不需要传入             
#                                                               
# 方式2： 基于环境变量导入账号和密钥                                                        
#   export HMAC_USER=<HMAC账号>                                
#   export HMAC_SECRET=<HMAC密钥>                                
#   export BODY_STRING=<请求Body字符串> [可选，默认不用传]     
#   bash hmac_auth.sh
##################################################################


# 检查是否安装了openssl
init_check() {
    export openssl_bin=$(which openssl)
    if [[ $? -ne 0 ]];then
        echo "Openssl can not found. Plz install it before."
        exit 3
    fi
}

# 生成 body digest 字符串
# 参数1: 请求Body的字符串，若网关开启了body校验，需要传入body内容，否则不传入即可
get_body_digest() {
    body_digest=$(echo -n ${1} | ${openssl_bin} dgst -sha256 -binary | base64)
    echo "SHA-256=${body_digest}"
}


# 获取签名
# 参数1: GMT格式时间
# 参数2: body digest
# 参数3: HMAC密钥
get_signature() {
    echo -en "date: ${1}\ndigest: ${2}" | ${openssl_bin} dgst -sha256 -hmac ${3} -binary | base64
}


# 组装验签头部
# 参数1: HMAC账号
# 参数2: HMAC密钥
# 参数3: 请求Body的字符串内容（可选），默认不需要传入
get_auth_headers() {
    hmac_user=$1
    hmac_secret=$2
    body_content=${3:''}
    gm_time=$(env LC_ALL=en_US.UTF-8 date -u '+%a, %d %b %Y %T GMT')
    body_digest="$(get_body_digest ${body_content})"
    signature=$(get_signature "${gm_time}" ${body_digest} ${hmac_secret})
    printf -- "-H 'Authorization:hmac username=\"$1\", algorithm=\"hmac-sha256\", headers=\"date digest\", signature=\"${signature}\"' -H 'Digest:${body_digest}' -H 'Date:${gm_time}'"
}


hmac_user="${1:-$HMAC_USER}"
hmac_secret="${2:-$HMAC_SECRET}"

if [ -z $hmac_user -o -z $hmac_secret ];then
    echo "Usage1: bash ${0} <HMAC_USER> <HMAC_SECRET> [BODY_STRING]
Usage2: 
    export HMAC_USER=xxxxxxxxx 
    export HMAC_SECRET=xxxxxxxx
    export BODY_STRING=xxxxxxxx [OPTIONAL]
    bash ${0}"
    exit 2
fi

init_check
get_auth_headers ${hmac_user} ${hmac_secret}
